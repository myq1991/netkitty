import {JSONSchema7, JSONSchema7Definition} from 'json-schema'
import {ProtocolFieldJSONSchemaDefinition} from './ProtocolFieldJSONSchemaDefinition'

export interface ProtocolJSONSchema extends JSONSchema7 {
    $defs?: {
        [key: string]: JSONSchema7Definition;
    } | undefined;

    items?: ProtocolFieldJSONSchemaDefinition | ProtocolFieldJSONSchemaDefinition[] | undefined;
    additionalItems?: JSONSchema7Definition | undefined;
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
