export function GetBinding(path: string): any {
    //Dynamic require: the native addon path is resolved at run time (node-gyp-build output), so a
    //static import is not possible here.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require(path)
}
