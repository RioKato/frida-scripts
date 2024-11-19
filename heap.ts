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
    super(address)
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

  bins(i: number): Bin | null {
    if (i >= 127) {
      throw new RangeError('index out of bounds')
    }

    const head = this.address.add(0x70 + 8 * 2 * i - 0x10)
    return new Bin(head, head)
  }
}

function traceHeap() {
  console.log(DebugSymbol.getFunctionByName('malloc'))
  console.log(DebugSymbol.getFunctionByName('hoo'))

  Interceptor.attach(DebugSymbol.getFunctionByName('malloc'), {
    onEnter() {
      DebugSymbol.getFunctionByName('hoo')
    }
  })
}

traceHeap()
