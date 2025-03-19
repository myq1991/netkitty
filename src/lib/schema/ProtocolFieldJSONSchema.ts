import {JSONSchema7} from 'json-schema'
import {ProtocolFieldJSONSchemaDefinition} from './ProtocolFieldJSONSchemaDefinition'

export interface ProtocolFieldJSONSchema extends JSONSchema7 {

    encode: () => void | Promise<void>

    decode: () => void | Promise<void>

    $defs?: {
        [key: string]: ProtocolFieldJSONSchemaDefinition;
    } | undefined;

    items?: ProtocolFieldJSONSchemaDefinition | ProtocolFieldJSONSchemaDefinition[] | undefined;
    additionalItems?: ProtocolFieldJSONSchemaDefinition | undefined;
    contains?: ProtocolFieldJSONSchemaDefinition | undefined;

    properties?: {
        [key: string]: ProtocolFieldJSONSchemaDefinition;
    } | undefined;
    patternProperties?: {
        [key: string]: ProtocolFieldJSONSchemaDefinition;
    } | undefined;
    additionalProperties?: ProtocolFieldJSONSchemaDefinition | undefined;
    dependencies?: {
        [key: string]: ProtocolFieldJSONSchemaDefinition | string[];
    } | undefined;
    propertyNames?: ProtocolFieldJSONSchemaDefinition | undefined;

    if?: ProtocolFieldJSONSchemaDefinition | undefined;
    then?: ProtocolFieldJSONSchemaDefinition | undefined;
    else?: ProtocolFieldJSONSchemaDefinition | undefined;

    allOf?: ProtocolFieldJSONSchemaDefinition[] | undefined;
    anyOf?: ProtocolFieldJSONSchemaDefinition[] | undefined;
    oneOf?: ProtocolFieldJSONSchemaDefinition[] | undefined;
    not?: ProtocolFieldJSONSchemaDefinition | undefined;

    definitions?: {
        [key: string]: ProtocolFieldJSONSchemaDefinition;
    } | undefined;
}
