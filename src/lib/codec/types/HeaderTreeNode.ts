export type HeaderTreeNodeField = string | number | boolean | HeaderTreeNode

export type HeaderTreeNode = {
    [field: string]: HeaderTreeNodeField | HeaderTreeNodeField[]
}
