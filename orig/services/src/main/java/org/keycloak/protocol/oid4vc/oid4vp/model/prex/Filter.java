/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oid4vc.oid4vp.model.prex;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import javax.annotation.processing.Generated;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;


/**
 * Core schema meta-schema
 * <p>
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder({"$id", "$schema", "$ref", "$comment", "title", "description", "default", "readOnly", "writeOnly", "examples", "multipleOf", "maximum", "exclusiveMaximum", "minimum", "exclusiveMinimum", "maxLength", "minLength", "pattern", "additionalItems", "items", "maxItems", "minItems", "uniqueItems", "contains", "maxProperties", "minProperties", "required", "const", "enum", "type", "format", "contentMediaType", "contentEncoding", "if", "then", "else", "allOf", "anyOf", "oneOf", "not"})
@Generated("jsonschema2pojo")
public class Filter {

    @JsonProperty("$id")
    private String $id;
    @JsonProperty("$schema")
    private URI $schema;
    @JsonProperty("$ref")
    private String $ref;
    @JsonProperty("$comment")
    private String $comment;
    @JsonProperty("title")
    private String title;
    @JsonProperty("description")
    private String description;
    @JsonProperty("default")
    private Object _default;
    @JsonProperty("readOnly")
    private Boolean readOnly;
    @JsonProperty("writeOnly")
    private Boolean writeOnly;
    @JsonProperty("examples")
    private List<Object> examples = new ArrayList<Object>();
    @JsonProperty("multipleOf")
    private Double multipleOf;
    @JsonProperty("maximum")
    private Double maximum;
    @JsonProperty("exclusiveMaximum")
    private Double exclusiveMaximum;
    @JsonProperty("minimum")
    private Double minimum;
    @JsonProperty("exclusiveMinimum")
    private Double exclusiveMinimum;
    @JsonProperty("maxLength")
    private Integer maxLength;
    @JsonProperty("minLength")
    private Object minLength;
    @JsonProperty("pattern")
    private Pattern pattern;
    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("additionalItems")
    private Filter additionalItems = null;
    @JsonProperty("items")
    private Object items = null;
    @JsonProperty("maxItems")
    private Integer maxItems;
    @JsonProperty("minItems")
    private Object minItems;
    @JsonProperty("uniqueItems")
    private Boolean uniqueItems;
    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("contains")
    private Filter contains = null;
    @JsonProperty("maxProperties")
    private Integer maxProperties;
    @JsonProperty("minProperties")
    private Object minProperties;
    @JsonProperty("required")
    @JsonDeserialize(as = LinkedHashSet.class)
    private Set<String> required = new LinkedHashSet<String>();
    @JsonProperty("const")
    private Object _const;
    @JsonProperty("enum")
    @JsonDeserialize(as = LinkedHashSet.class)
    private Set<Object> _enum = new LinkedHashSet<Object>();
    @JsonProperty("type")
    private SimpleTypes type;
    @JsonProperty("format")
    private String format;
    @JsonProperty("contentMediaType")
    private String contentMediaType;
    @JsonProperty("contentEncoding")
    private String contentEncoding;
    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("if")
    private Filter _if = null;
    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("then")
    private Filter then = null;
    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("else")
    private Filter _else = null;
    @JsonProperty("allOf")
    private List<Filter> allOf = new ArrayList<Filter>();
    @JsonProperty("anyOf")
    private List<Filter> anyOf = new ArrayList<Filter>();
    @JsonProperty("oneOf")
    private List<Filter> oneOf = new ArrayList<Filter>();
    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("not")
    private Filter not = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new LinkedHashMap<String, Object>();

    @JsonProperty("$id")
    public String get$id() {
        return $id;
    }

    @JsonProperty("$id")
    public void set$id(String $id) {
        this.$id = $id;
    }

    @JsonProperty("$schema")
    public URI get$schema() {
        return $schema;
    }

    @JsonProperty("$schema")
    public void set$schema(URI $schema) {
        this.$schema = $schema;
    }

    @JsonProperty("$ref")
    public String get$ref() {
        return $ref;
    }

    @JsonProperty("$ref")
    public void set$ref(String $ref) {
        this.$ref = $ref;
    }

    @JsonProperty("$comment")
    public String get$comment() {
        return $comment;
    }

    @JsonProperty("$comment")
    public void set$comment(String $comment) {
        this.$comment = $comment;
    }

    @JsonProperty("title")
    public String getTitle() {
        return title;
    }

    @JsonProperty("title")
    public void setTitle(String title) {
        this.title = title;
    }

    @JsonProperty("description")
    public String getDescription() {
        return description;
    }

    @JsonProperty("description")
    public void setDescription(String description) {
        this.description = description;
    }

    @JsonProperty("default")
    public Object getDefault() {
        return _default;
    }

    @JsonProperty("default")
    public void setDefault(Object _default) {
        this._default = _default;
    }

    @JsonProperty("readOnly")
    public Boolean getReadOnly() {
        return readOnly;
    }

    @JsonProperty("readOnly")
    public void setReadOnly(Boolean readOnly) {
        this.readOnly = readOnly;
    }

    @JsonProperty("writeOnly")
    public Boolean getWriteOnly() {
        return writeOnly;
    }

    @JsonProperty("writeOnly")
    public void setWriteOnly(Boolean writeOnly) {
        this.writeOnly = writeOnly;
    }

    @JsonProperty("examples")
    public List<Object> getExamples() {
        return examples;
    }

    @JsonProperty("examples")
    public void setExamples(List<Object> examples) {
        this.examples = examples;
    }

    @JsonProperty("multipleOf")
    public Double getMultipleOf() {
        return multipleOf;
    }

    @JsonProperty("multipleOf")
    public void setMultipleOf(Double multipleOf) {
        this.multipleOf = multipleOf;
    }

    @JsonProperty("maximum")
    public Double getMaximum() {
        return maximum;
    }

    @JsonProperty("maximum")
    public void setMaximum(Double maximum) {
        this.maximum = maximum;
    }

    @JsonProperty("exclusiveMaximum")
    public Double getExclusiveMaximum() {
        return exclusiveMaximum;
    }

    @JsonProperty("exclusiveMaximum")
    public void setExclusiveMaximum(Double exclusiveMaximum) {
        this.exclusiveMaximum = exclusiveMaximum;
    }

    @JsonProperty("minimum")
    public Double getMinimum() {
        return minimum;
    }

    @JsonProperty("minimum")
    public void setMinimum(Double minimum) {
        this.minimum = minimum;
    }

    @JsonProperty("exclusiveMinimum")
    public Double getExclusiveMinimum() {
        return exclusiveMinimum;
    }

    @JsonProperty("exclusiveMinimum")
    public void setExclusiveMinimum(Double exclusiveMinimum) {
        this.exclusiveMinimum = exclusiveMinimum;
    }

    @JsonProperty("maxLength")
    public Integer getMaxLength() {
        return maxLength;
    }

    @JsonProperty("maxLength")
    public void setMaxLength(Integer maxLength) {
        this.maxLength = maxLength;
    }

    @JsonProperty("minLength")
    public Object getMinLength() {
        return minLength;
    }

    @JsonProperty("minLength")
    public void setMinLength(Object minLength) {
        this.minLength = minLength;
    }

    @JsonProperty("pattern")
    public Pattern getPattern() {
        return pattern;
    }

    @JsonProperty("pattern")
    public void setPattern(Pattern pattern) {
        this.pattern = pattern;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("additionalItems")
    public Filter getAdditionalItems() {
        return additionalItems;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("additionalItems")
    public void setAdditionalItems(Filter additionalItems) {
        this.additionalItems = additionalItems;
    }

    @JsonProperty("items")
    public Object getItems() {
        return items;
    }

    @JsonProperty("items")
    public void setItems(Object items) {
        this.items = items;
    }

    @JsonProperty("maxItems")
    public Integer getMaxItems() {
        return maxItems;
    }

    @JsonProperty("maxItems")
    public void setMaxItems(Integer maxItems) {
        this.maxItems = maxItems;
    }

    @JsonProperty("minItems")
    public Object getMinItems() {
        return minItems;
    }

    @JsonProperty("minItems")
    public void setMinItems(Object minItems) {
        this.minItems = minItems;
    }

    @JsonProperty("uniqueItems")
    public Boolean getUniqueItems() {
        return uniqueItems;
    }

    @JsonProperty("uniqueItems")
    public void setUniqueItems(Boolean uniqueItems) {
        this.uniqueItems = uniqueItems;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("contains")
    public Filter getContains() {
        return contains;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("contains")
    public void setContains(Filter contains) {
        this.contains = contains;
    }

    @JsonProperty("maxProperties")
    public Integer getMaxProperties() {
        return maxProperties;
    }

    @JsonProperty("maxProperties")
    public void setMaxProperties(Integer maxProperties) {
        this.maxProperties = maxProperties;
    }

    @JsonProperty("minProperties")
    public Object getMinProperties() {
        return minProperties;
    }

    @JsonProperty("minProperties")
    public void setMinProperties(Object minProperties) {
        this.minProperties = minProperties;
    }

    @JsonProperty("required")
    public Set<String> getRequired() {
        return required;
    }

    @JsonProperty("required")
    public void setRequired(Set<String> required) {
        this.required = required;
    }

    @JsonProperty("const")
    public Object getConst() {
        return _const;
    }

    @JsonProperty("const")
    public void setConst(Object _const) {
        this._const = _const;
    }

    @JsonProperty("enum")
    public Set<Object> getEnum() {
        return _enum;
    }

    @JsonProperty("enum")
    public void setEnum(Set<Object> _enum) {
        this._enum = _enum;
    }

    @JsonProperty("type")
    public SimpleTypes getType() {
        return type;
    }

    @JsonProperty("type")
    public void setType(SimpleTypes type) {
        this.type = type;
    }

    @JsonProperty("format")
    public String getFormat() {
        return format;
    }

    @JsonProperty("format")
    public void setFormat(String format) {
        this.format = format;
    }

    @JsonProperty("contentMediaType")
    public String getContentMediaType() {
        return contentMediaType;
    }

    @JsonProperty("contentMediaType")
    public void setContentMediaType(String contentMediaType) {
        this.contentMediaType = contentMediaType;
    }

    @JsonProperty("contentEncoding")
    public String getContentEncoding() {
        return contentEncoding;
    }

    @JsonProperty("contentEncoding")
    public void setContentEncoding(String contentEncoding) {
        this.contentEncoding = contentEncoding;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("if")
    public Filter getIf() {
        return _if;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("if")
    public void setIf(Filter _if) {
        this._if = _if;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("then")
    public Filter getThen() {
        return then;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("then")
    public void setThen(Filter then) {
        this.then = then;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("else")
    public Filter getElse() {
        return _else;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("else")
    public void setElse(Filter _else) {
        this._else = _else;
    }

    @JsonProperty("allOf")
    public List<Filter> getAllOf() {
        return allOf;
    }

    @JsonProperty("allOf")
    public void setAllOf(List<Filter> allOf) {
        this.allOf = allOf;
    }

    @JsonProperty("anyOf")
    public List<Filter> getAnyOf() {
        return anyOf;
    }

    @JsonProperty("anyOf")
    public void setAnyOf(List<Filter> anyOf) {
        this.anyOf = anyOf;
    }

    @JsonProperty("oneOf")
    public List<Filter> getOneOf() {
        return oneOf;
    }

    @JsonProperty("oneOf")
    public void setOneOf(List<Filter> oneOf) {
        this.oneOf = oneOf;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("not")
    public Filter getNot() {
        return not;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("not")
    public void setNot(Filter not) {
        this.not = not;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(Filter.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("$id");
        sb.append('=');
        sb.append(((this.$id == null) ? "<null>" : this.$id));
        sb.append(',');
        sb.append("$schema");
        sb.append('=');
        sb.append(((this.$schema == null) ? "<null>" : this.$schema));
        sb.append(',');
        sb.append("$ref");
        sb.append('=');
        sb.append(((this.$ref == null) ? "<null>" : this.$ref));
        sb.append(',');
        sb.append("$comment");
        sb.append('=');
        sb.append(((this.$comment == null) ? "<null>" : this.$comment));
        sb.append(',');
        sb.append("title");
        sb.append('=');
        sb.append(((this.title == null) ? "<null>" : this.title));
        sb.append(',');
        sb.append("description");
        sb.append('=');
        sb.append(((this.description == null) ? "<null>" : this.description));
        sb.append(',');
        sb.append("_default");
        sb.append('=');
        sb.append(((this._default == null) ? "<null>" : this._default));
        sb.append(',');
        sb.append("readOnly");
        sb.append('=');
        sb.append(((this.readOnly == null) ? "<null>" : this.readOnly));
        sb.append(',');
        sb.append("writeOnly");
        sb.append('=');
        sb.append(((this.writeOnly == null) ? "<null>" : this.writeOnly));
        sb.append(',');
        sb.append("examples");
        sb.append('=');
        sb.append(((this.examples == null) ? "<null>" : this.examples));
        sb.append(',');
        sb.append("multipleOf");
        sb.append('=');
        sb.append(((this.multipleOf == null) ? "<null>" : this.multipleOf));
        sb.append(',');
        sb.append("maximum");
        sb.append('=');
        sb.append(((this.maximum == null) ? "<null>" : this.maximum));
        sb.append(',');
        sb.append("exclusiveMaximum");
        sb.append('=');
        sb.append(((this.exclusiveMaximum == null) ? "<null>" : this.exclusiveMaximum));
        sb.append(',');
        sb.append("minimum");
        sb.append('=');
        sb.append(((this.minimum == null) ? "<null>" : this.minimum));
        sb.append(',');
        sb.append("exclusiveMinimum");
        sb.append('=');
        sb.append(((this.exclusiveMinimum == null) ? "<null>" : this.exclusiveMinimum));
        sb.append(',');
        sb.append("maxLength");
        sb.append('=');
        sb.append(((this.maxLength == null) ? "<null>" : this.maxLength));
        sb.append(',');
        sb.append("minLength");
        sb.append('=');
        sb.append(((this.minLength == null) ? "<null>" : this.minLength));
        sb.append(',');
        sb.append("pattern");
        sb.append('=');
        sb.append(((this.pattern == null) ? "<null>" : this.pattern));
        sb.append(',');
        sb.append("additionalItems");
        sb.append('=');
        sb.append(((this.additionalItems == null) ? "<null>" : this.additionalItems));
        sb.append(',');
        sb.append("items");
        sb.append('=');
        sb.append(((this.items == null) ? "<null>" : this.items));
        sb.append(',');
        sb.append("maxItems");
        sb.append('=');
        sb.append(((this.maxItems == null) ? "<null>" : this.maxItems));
        sb.append(',');
        sb.append("minItems");
        sb.append('=');
        sb.append(((this.minItems == null) ? "<null>" : this.minItems));
        sb.append(',');
        sb.append("uniqueItems");
        sb.append('=');
        sb.append(((this.uniqueItems == null) ? "<null>" : this.uniqueItems));
        sb.append(',');
        sb.append("contains");
        sb.append('=');
        sb.append(((this.contains == null) ? "<null>" : this.contains));
        sb.append(',');
        sb.append("maxProperties");
        sb.append('=');
        sb.append(((this.maxProperties == null) ? "<null>" : this.maxProperties));
        sb.append(',');
        sb.append("minProperties");
        sb.append('=');
        sb.append(((this.minProperties == null) ? "<null>" : this.minProperties));
        sb.append(',');
        sb.append("required");
        sb.append('=');
        sb.append(((this.required == null) ? "<null>" : this.required));
        sb.append(',');
        sb.append("_const");
        sb.append('=');
        sb.append(((this._const == null) ? "<null>" : this._const));
        sb.append(',');
        sb.append("_enum");
        sb.append('=');
        sb.append(((this._enum == null) ? "<null>" : this._enum));
        sb.append(',');
        sb.append("type");
        sb.append('=');
        sb.append(((this.type == null) ? "<null>" : this.type));
        sb.append(',');
        sb.append("format");
        sb.append('=');
        sb.append(((this.format == null) ? "<null>" : this.format));
        sb.append(',');
        sb.append("contentMediaType");
        sb.append('=');
        sb.append(((this.contentMediaType == null) ? "<null>" : this.contentMediaType));
        sb.append(',');
        sb.append("contentEncoding");
        sb.append('=');
        sb.append(((this.contentEncoding == null) ? "<null>" : this.contentEncoding));
        sb.append(',');
        sb.append("_if");
        sb.append('=');
        sb.append(((this._if == null) ? "<null>" : this._if));
        sb.append(',');
        sb.append("then");
        sb.append('=');
        sb.append(((this.then == null) ? "<null>" : this.then));
        sb.append(',');
        sb.append("_else");
        sb.append('=');
        sb.append(((this._else == null) ? "<null>" : this._else));
        sb.append(',');
        sb.append("allOf");
        sb.append('=');
        sb.append(((this.allOf == null) ? "<null>" : this.allOf));
        sb.append(',');
        sb.append("anyOf");
        sb.append('=');
        sb.append(((this.anyOf == null) ? "<null>" : this.anyOf));
        sb.append(',');
        sb.append("oneOf");
        sb.append('=');
        sb.append(((this.oneOf == null) ? "<null>" : this.oneOf));
        sb.append(',');
        sb.append("not");
        sb.append('=');
        sb.append(((this.not == null) ? "<null>" : this.not));
        sb.append(',');
        sb.append("additionalProperties");
        sb.append('=');
        sb.append(((this.additionalProperties == null) ? "<null>" : this.additionalProperties));
        sb.append(',');
        if (sb.charAt((sb.length() - 1)) == ',') {
            sb.setCharAt((sb.length() - 1), ']');
        } else {
            sb.append(']');
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int result = 1;
        result = ((result * 31) + ((this.writeOnly == null) ? 0 : this.writeOnly.hashCode()));
        result = ((result * 31) + ((this.$schema == null) ? 0 : this.$schema.hashCode()));
        result = ((result * 31) + ((this.minLength == null) ? 0 : this.minLength.hashCode()));
        result = ((result * 31) + ((this.pattern == null) ? 0 : this.pattern.hashCode()));
        result = ((result * 31) + ((this.description == null) ? 0 : this.description.hashCode()));
        result = ((result * 31) + ((this._enum == null) ? 0 : this._enum.hashCode()));
        result = ((result * 31) + ((this.title == null) ? 0 : this.title.hashCode()));
        result = ((result * 31) + ((this.type == null) ? 0 : this.type.hashCode()));
        result = ((result * 31) + ((this.required == null) ? 0 : this.required.hashCode()));
        result = ((result * 31) + ((this.exclusiveMaximum == null) ? 0 : this.exclusiveMaximum.hashCode()));
        result = ((result * 31) + ((this.allOf == null) ? 0 : this.allOf.hashCode()));
        result = ((result * 31) + ((this.oneOf == null) ? 0 : this.oneOf.hashCode()));
        result = ((result * 31) + ((this.not == null) ? 0 : this.not.hashCode()));
        result = ((result * 31) + ((this.additionalItems == null) ? 0 : this.additionalItems.hashCode()));
        result = ((result * 31) + ((this.contentEncoding == null) ? 0 : this.contentEncoding.hashCode()));
        result = ((result * 31) + ((this.maxProperties == null) ? 0 : this.maxProperties.hashCode()));
        result = ((result * 31) + ((this.exclusiveMinimum == null) ? 0 : this.exclusiveMinimum.hashCode()));
        result = ((result * 31) + ((this.multipleOf == null) ? 0 : this.multipleOf.hashCode()));
        result = ((result * 31) + ((this._default == null) ? 0 : this._default.hashCode()));
        result = ((result * 31) + ((this.maxItems == null) ? 0 : this.maxItems.hashCode()));
        result = ((result * 31) + ((this.contentMediaType == null) ? 0 : this.contentMediaType.hashCode()));
        result = ((result * 31) + ((this._const == null) ? 0 : this._const.hashCode()));
        result = ((result * 31) + ((this.format == null) ? 0 : this.format.hashCode()));
        result = ((result * 31) + ((this.anyOf == null) ? 0 : this.anyOf.hashCode()));
        result = ((result * 31) + ((this.readOnly == null) ? 0 : this.readOnly.hashCode()));
        result = ((result * 31) + ((this.$comment == null) ? 0 : this.$comment.hashCode()));
        result = ((result * 31) + ((this.then == null) ? 0 : this.then.hashCode()));
        result = ((result * 31) + ((this.minProperties == null) ? 0 : this.minProperties.hashCode()));
        result = ((result * 31) + ((this.minItems == null) ? 0 : this.minItems.hashCode()));
        result = ((result * 31) + ((this.contains == null) ? 0 : this.contains.hashCode()));
        result = ((result * 31) + ((this._else == null) ? 0 : this._else.hashCode()));
        result = ((result * 31) + ((this.examples == null) ? 0 : this.examples.hashCode()));
        result = ((result * 31) + ((this.uniqueItems == null) ? 0 : this.uniqueItems.hashCode()));
        result = ((result * 31) + ((this.maximum == null) ? 0 : this.maximum.hashCode()));
        result = ((result * 31) + ((this.additionalProperties == null) ? 0 : this.additionalProperties.hashCode()));
        result = ((result * 31) + ((this.$ref == null) ? 0 : this.$ref.hashCode()));
        result = ((result * 31) + ((this.minimum == null) ? 0 : this.minimum.hashCode()));
        result = ((result * 31) + ((this.items == null) ? 0 : this.items.hashCode()));
        result = ((result * 31) + ((this._if == null) ? 0 : this._if.hashCode()));
        result = ((result * 31) + ((this.maxLength == null) ? 0 : this.maxLength.hashCode()));
        result = ((result * 31) + ((this.$id == null) ? 0 : this.$id.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Filter) == false) {
            return false;
        }
        Filter rhs = ((Filter) other);
        return ((((((((((((((((((((((((((((((((((((((((((this.writeOnly == rhs.writeOnly) || ((this.writeOnly != null) && this.writeOnly.equals(rhs.writeOnly))) && ((this.$schema == rhs.$schema) || ((this.$schema != null) && this.$schema.equals(rhs.$schema)))) && ((this.minLength == rhs.minLength) || ((this.minLength != null) && this.minLength.equals(rhs.minLength)))) && ((this.pattern == rhs.pattern) || ((this.pattern != null) && this.pattern.equals(rhs.pattern)))) && ((this.description == rhs.description) || ((this.description != null) && this.description.equals(rhs.description)))) && ((this._enum == rhs._enum) || ((this._enum != null) && this._enum.equals(rhs._enum)))) && ((this.title == rhs.title) || ((this.title != null) && this.title.equals(rhs.title)))) && ((this.type == rhs.type) || ((this.type != null) && this.type.equals(rhs.type)))) && ((this.required == rhs.required) || ((this.required != null) && this.required.equals(rhs.required)))) && ((this.exclusiveMaximum == rhs.exclusiveMaximum) || ((this.exclusiveMaximum != null) && this.exclusiveMaximum.equals(rhs.exclusiveMaximum)))) && ((this.allOf == rhs.allOf) || ((this.allOf != null) && this.allOf.equals(rhs.allOf)))) && ((this.oneOf == rhs.oneOf) || ((this.oneOf != null) && this.oneOf.equals(rhs.oneOf)))) && ((this.not == rhs.not) || ((this.not != null) && this.not.equals(rhs.not)))) && ((this.additionalItems == rhs.additionalItems) || ((this.additionalItems != null) && this.additionalItems.equals(rhs.additionalItems)))) && ((this.contentEncoding == rhs.contentEncoding) || ((this.contentEncoding != null) && this.contentEncoding.equals(rhs.contentEncoding)))) && ((this.maxProperties == rhs.maxProperties) || ((this.maxProperties != null) && this.maxProperties.equals(rhs.maxProperties)))) && ((this.exclusiveMinimum == rhs.exclusiveMinimum) || ((this.exclusiveMinimum != null) && this.exclusiveMinimum.equals(rhs.exclusiveMinimum)))) && ((this.multipleOf == rhs.multipleOf) || ((this.multipleOf != null) && this.multipleOf.equals(rhs.multipleOf)))) && ((this._default == rhs._default) || ((this._default != null) && this._default.equals(rhs._default)))) && ((this.maxItems == rhs.maxItems) || ((this.maxItems != null) && this.maxItems.equals(rhs.maxItems)))) && ((this.contentMediaType == rhs.contentMediaType) || ((this.contentMediaType != null) && this.contentMediaType.equals(rhs.contentMediaType)))) && ((this._const == rhs._const) || ((this._const != null) && this._const.equals(rhs._const)))) && ((this.format == rhs.format) || ((this.format != null) && this.format.equals(rhs.format)))) && ((this.anyOf == rhs.anyOf) || ((this.anyOf != null) && this.anyOf.equals(rhs.anyOf)))) && ((this.readOnly == rhs.readOnly) || ((this.readOnly != null) && this.readOnly.equals(rhs.readOnly)))) && ((this.$comment == rhs.$comment) || ((this.$comment != null) && this.$comment.equals(rhs.$comment)))) && ((this.then == rhs.then) || ((this.then != null) && this.then.equals(rhs.then)))) && ((this.minProperties == rhs.minProperties) || ((this.minProperties != null) && this.minProperties.equals(rhs.minProperties)))) && ((this.minItems == rhs.minItems) || ((this.minItems != null) && this.minItems.equals(rhs.minItems)))) && ((this.contains == rhs.contains) || ((this.contains != null) && this.contains.equals(rhs.contains)))) && ((this._else == rhs._else) || ((this._else != null) && this._else.equals(rhs._else)))) && ((this.examples == rhs.examples) || ((this.examples != null) && this.examples.equals(rhs.examples)))) && ((this.uniqueItems == rhs.uniqueItems) || ((this.uniqueItems != null) && this.uniqueItems.equals(rhs.uniqueItems)))) && ((this.maximum == rhs.maximum) || ((this.maximum != null) && this.maximum.equals(rhs.maximum)))) && ((this.additionalProperties == rhs.additionalProperties) || ((this.additionalProperties != null) && this.additionalProperties.equals(rhs.additionalProperties)))) && ((this.$ref == rhs.$ref) || ((this.$ref != null) && this.$ref.equals(rhs.$ref)))) && ((this.minimum == rhs.minimum) || ((this.minimum != null) && this.minimum.equals(rhs.minimum)))) && ((this.items == rhs.items) || ((this.items != null) && this.items.equals(rhs.items)))) && ((this._if == rhs._if) || ((this._if != null) && this._if.equals(rhs._if)))) && ((this.maxLength == rhs.maxLength) || ((this.maxLength != null) && this.maxLength.equals(rhs.maxLength)))) && ((this.$id == rhs.$id) || ((this.$id != null) && this.$id.equals(rhs.$id))));
    }

    @Generated("jsonschema2pojo")
    public enum SimpleTypes {

        ARRAY("array"), BOOLEAN("boolean"), INTEGER("integer"), NULL("null"), NUMBER("number"), OBJECT("object"), STRING("string");
        private final static Map<String, SimpleTypes> CONSTANTS = new HashMap<String, SimpleTypes>();

        static {
            for (SimpleTypes c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        SimpleTypes(String value) {
            this.value = value;
        }

        @JsonCreator
        public static SimpleTypes fromValue(String value) {
            SimpleTypes constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

    }

}
