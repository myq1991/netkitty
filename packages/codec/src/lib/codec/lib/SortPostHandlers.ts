import {PostHandlerItem} from '../types/PostHandlerItem'

/**
 * Sort post handlers
 * @param handlers
 * @constructor
 */
export function SortPostHandlers(handlers: PostHandlerItem[]): PostHandlerItem[] {
    return handlers.sort((a: PostHandlerItem, b: PostHandlerItem): number => a.priority - b.priority)
}
