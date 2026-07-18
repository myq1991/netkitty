export type PostHandlerItem = {
    priority: number
    handler: () => void | Promise<void>
}
