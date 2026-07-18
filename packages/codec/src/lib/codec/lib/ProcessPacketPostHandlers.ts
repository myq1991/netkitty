import {PostHandlerItem} from '../types/PostHandlerItem'
import {SortPostHandlers} from './SortPostHandlers'

/**
 * Process packet post handlers
 * @param handlerItemsArray
 * @param asc
 */
function processPacketPostHandlers(handlerItemsArray: PostHandlerItem[][], asc: boolean): PostHandlerItem[][] {
    let indexFactor: number = 10
    return handlerItemsArray
        .map((handlerItems: PostHandlerItem[]): PostHandlerItem[] => {
            return SortPostHandlers(handlerItems).map((handlerItem: PostHandlerItem, index: number): PostHandlerItem => {
                handlerItem.priority = index + 1
                let factor: number = 10
                let priority: number = handlerItem.priority
                while (priority > 1) {
                    priority /= 10
                    factor *= 10
                }
                indexFactor = indexFactor < factor ? factor : indexFactor
                return handlerItem
            })
        })
        .map((handlerItems: PostHandlerItem[], headerIndex: number): PostHandlerItem[] => {
            const basePriority: number = (headerIndex + 1) * indexFactor
            const unsortedItems: PostHandlerItem[] = handlerItems.map((handlerItem: PostHandlerItem): PostHandlerItem => {
                handlerItem.priority = basePriority + handlerItem.priority
                return handlerItem
            })
            return asc ?
                unsortedItems.sort((a: PostHandlerItem, b: PostHandlerItem): number => a.priority - b.priority) :
                unsortedItems.sort((a: PostHandlerItem, b: PostHandlerItem): number => b.priority - a.priority)
        })
}

/**
 * Process packet post encode handlers
 * @param handlerItemsArray
 * @constructor
 */
export function ProcessPacketEncodePostHandlers(handlerItemsArray: PostHandlerItem[][]): PostHandlerItem[] {
    return processPacketPostHandlers(handlerItemsArray, true).reverse().flat()
}

/**
 * Process packet post decode handlers
 * @param handlerItemsArray
 * @constructor
 */
export function ProcessPacketDecodePostHandlers(handlerItemsArray: PostHandlerItem[][]): PostHandlerItem[] {
    return processPacketPostHandlers(handlerItemsArray, true).flat()
}
