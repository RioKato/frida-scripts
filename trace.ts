function traceJava(query: string) {
  Java.perform(() => {
    Java.enumerateMethods(query).forEach((value, index, result) => {
      for (const loader of result) {
        for (const cls of loader.classes) {
          const jcls = Java.use(cls.name)

          for (const method of cls.methods) {
            for (const overload of jcls[method].overloads) {

              overload.implementation = function(...args: any[]) {
                const retval = overload.apply(this, args)
                console.log(`${cls.name}.${method}(${args.map(arg => JSON.stringify(arg)).join(',')}) = ${retval}`)
                return retval
              }
            }
          }
        }
      }
    })
  })
}
