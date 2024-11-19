function getHeapRange(): RangeDetails {
  const sbrk = DebugSymbol.getFunctionByName('sbrk')
  const sbrkfn = new NativeFunction(sbrk, 'pointer', ['pointer'])
  const top = sbrkfn(new NativePointer(0))

  for (const range of Process.enumerateRanges('rw-')) {
    if (range.base.compare(top) <= 0 && range.base.add(range.size).compare(top) >= 0) {
      return range
    }
  }

  throw new Error('unable to get heap range')
}

function getLibcModule(): Module {
  return Process.getModuleByName('libc.so.6')
}

class Chunk {
  address: NativePointer

  constructor(address: NativePointer) {
    this.address = address
  }

  size(): UInt64 {
    return this.address.add(0x8).readU64()
  }

  fd(): NativePointer {
    return this.address.add(0x10).readPointer()
  }

  reveal(): NativePointer {
    const mask = this.address.add(0x10).shr(12)
    return this.fd().xor(mask)
  }

  bk(): NativePointer {
    return this.address.add(0x18).readPointer()
  }
}

class TcacheEntry extends Chunk {
  constructor(address: NativePointer) {
    super(address.sub(0x10))
  }

  next(): TcacheEntry | null {
    const reveal = this.reveal()
    return reveal.isNull() ? null : new TcacheEntry(reveal)
  }
}

class Tcache {
  address: NativePointer

  constructor(address: NativePointer) {
    this.address = address
  }

  counts(i: number): number {
    if (i >= 64) {
      throw new RangeError('index out of bounds')
    }

    return this.address.add(2 * i).readU16()
  }

  entries(i: number): TcacheEntry | null {
    if (i >= 64) {
      throw new RangeError('index out of bounds')
    }

    const next = this.address.add(0x80 + 8 * i).readPointer()
    return next.isNull() ? null : new TcacheEntry(next)
  }
}


class Fastbin extends Chunk {
  constructor(address: NativePointer) {
    super(address)
  }

  next(): Fastbin | null {
    const next = this.reveal()
    return next.isNull() ? null : new Fastbin(next)
  }
}

class Bin extends Chunk {
  head: NativePointer

  constructor(address: NativePointer, head: NativePointer) {
    super(address)
    this.head = head
  }

  next(): Bin | null {
    const next = this.fd()
    return next.equals(this.head) ? null : new Bin(next, this.head)
  }

  prev(): Bin | null {
    const prev = this.bk()
    return prev.equals(this.head) ? null : new Bin(prev, this.head)
  }
}

class MallocState {
  address: NativePointer

  constructor(address: NativePointer) {
    this.address = address
  }

  fastbinY(i: number): Fastbin | null {
    if (i >= 10) {
      throw new RangeError('index out of bounds')
    }

    const next = this.address.add(0x10 + 8 * i).readPointer()
    return next.isNull() ? null : new Fastbin(next)
  }

  top(): NativePointer {
    return this.address.add(0x60).readPointer()
  }

  bins(i: number): Bin {
    if (i >= 127) {
      throw new RangeError('index out of bounds')
    }

    const head = this.address.add(0x70 + 8 * 2 * i - 0x10)
    return new Bin(head, head)
  }
}

function dump(mstate: MallocState, tcache: Tcache) {
  let message = ''

  for (let i = 0; i < 64; i++) {
    let entries = []
    let entry = tcache.entries(i)

    while (entry) {
      let info = `0x${entry.address.toString(16)}`

      try {
        info += `:0x${entry.size().toString(16)}`
      } catch {
      }

      entries.push(info)

      try {
        entry = entry.next()
      } catch {
        entry = null
      }
    }

    if (entries.length) {
      message += `tcache[${i}](${tcache.counts(i)}): ${entries.join(' => ')}\n`
    }
  }

  for (let i = 0; i < 10; i++) {
    let entries = []
    let entry = mstate.fastbinY(i)

    while (entry) {
      let info = `0x${entry.address.toString(16)}`

      try {
        info += `:0x${entry.size().toString(16)}`
      } catch {
      }

      entries.push(info)

      try {
        entry = entry.next()
      } catch {
        entry = null
      }
    }

    if (entries.length) {
      message += `fastbin[${i}]: ${entries.join(' => ')}\n`
    }
  }

  for (let i = 0; i < 127; i++) {
    let entries = []
    let entry = mstate.bins(i).next()

    while (entry) {
      let info = `0x${entry.address.toString(16)}`

      try {
        info += `:0x${entry.size().toString(16)}`
      } catch {
      }

      entries.push(info)

      try {
        entry = entry.next()
      } catch {
        entry = null
      }
    }

    if (entries.length) {
      message += `bins[${i * 2}]: ${entries.join(' => ')}\n`
    }

    entries = []
    entry = mstate.bins(i).prev()

    while (entry) {
      let info = `0x${entry.address.toString(16)}`

      try {
        info += `:0x${entry.size().toString(16)}`
      } catch {
      }

      entries.push(info)

      try {
        entry = entry.prev()
      } catch {
        entry = null
      }
    }

    if (entries.length) {
      message += `bins[${i * 2 + 1}]: ${entries.join(' => ')}\n`
    }
  }

  if (message) {
    message = `top: ${mstate.top()}\n` + message
    console.log(message)
  }
}

function traceHeap() {
  const libc = getLibcModule()
  const heap = getHeapRange()
  const main_arena = new MallocState(libc.base.add(0x1e7ac0))
  const tcache = new Tcache(heap.base.add(0x10))

  Interceptor.attach(DebugSymbol.getFunctionByName('malloc'), {
    onEnter() {
      const context = this.context as X64CpuContext
      this.size = context.rdi
    },

    onLeave(reveal) {
      console.log('==========================================')
      console.log(`[*] ${reveal} = malloc(${this.size})`)
      console.log('')
      dump(main_arena, tcache)
    }
  })

  Interceptor.attach(DebugSymbol.getFunctionByName('free'), {
    onEnter() {
      const context = this.context as X64CpuContext
      this.target = context.rdi
    },

    onLeave() {
      console.log('==========================================')
      console.log(`[*] free(${this.target})`)
      console.log('')
      dump(main_arena, tcache)
    }
  })
}

traceHeap()
