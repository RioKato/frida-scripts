function traceC(query: string) {
  const resolver = new ApiResolver('module')

  resolver.enumerateMatches(query).forEach((value, index, result) => {
    for (const symbol of result) {
      Interceptor.attach(symbol.address, {
        onEnter(args) {
          console.log(`${' '.repeat(this.indent)}${symbol.name.split('!')[1]}() {`)
        },

        onLeave(retval) {
          console.log(`${' '.repeat(this.indent)}} = ${retval}`)
        },
      })
    }
  })
}

function traceJava(query: string) {
  Java.perform(() => {
    Java.enumerateMethods(query).forEach((value, index, result) => {
      for (const loader of result) {
        for (const cls of loader.classes) {
          const jcls = Java.use(cls.name)

          for (const method of cls.methods) {
            for (const overload of jcls[method].overloads) {

              overload.implementation = function(...args: any[]) {
                console.log(`${cls.name}.${method}(${args.map(arg => JSON.stringify(arg)).join(',')}) {`)
                const retval = overload.apply(this, args)
                console.log(`} = ${retval}`)
                return retval
              }
            }
          }
        }
      }
    })
  })
}
