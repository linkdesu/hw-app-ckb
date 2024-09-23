declare module 'bip32-path' {
  // Define types for the package
  export default class BIPPath {
    path: number[]

    static fromString (path: string): BIPPath;

    toPathArray (): number[];
  }
}
