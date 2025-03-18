import {JSONSchema7, JSONSchema7Definition, JSONSchema7Type} from 'json-schema'
import {JSONSchemaProtocolDefinition} from './JSONSchemaProtocolDefinition'

export type EncodeResult = Buffer
export type DecodeResult = {
    offset: number,
    length: number,
    label: string
    value: (number | string | boolean | object) | (number | string | boolean | object)[]
}

export interface JSONSchemaProtocol extends JSONSchema7 {

    $headerId?: number

    $prevHeaderRef?: string

    $nextHeaderRef?: string

    encode?: (input: any) => EncodeResult | Promise<EncodeResult>

    decode?: (data: Buffer) => DecodeResult | Promise<DecodeResult>

    $defs?: {
        [key: string]: JSONSchema7Definition;
    } | undefined;

    items?: JSONSchemaProtocolDefinition | JSONSchemaProtocolDefinition[] | undefined;
    additionalItems?: JSONSchema7Definition | undefined;
    contains?: JSONSchemaProtocolDefinition | undefined;

    properties?: {
        [key: string]: JSONSchemaProtocolDefinition;
    } | undefined;
    patternProperties?: {
        [key: string]: JSONSchemaProtocolDefinition;
    } | undefined;
    additionalProperties?: JSONSchemaProtocolDefinition | undefined;
    dependencies?: {
        [key: string]: JSONSchemaProtocolDefinition | string[];
    } | undefined;
    propertyNames?: JSONSchemaProtocolDefinition | undefined;

    if?: JSONSchemaProtocolDefinition | undefined;
    then?: JSONSchemaProtocolDefinition | undefined;
    else?: JSONSchemaProtocolDefinition | undefined;

    allOf?: JSONSchemaProtocolDefinition[] | undefined;
    anyOf?: JSONSchemaProtocolDefinition[] | undefined;
    oneOf?: JSONSchemaProtocolDefinition[] | undefined;
    not?: JSONSchemaProtocolDefinition | undefined;

    definitions?: {
        [key: string]: JSONSchemaProtocolDefinition;
    } | undefined;

    default?: JSONSchema7Type | undefined;
    examples?: JSONSchema7Type | undefined;
}
