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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import javax.annotation.processing.Generated;


/**
 * Presentation Definition Claim Format Designations
 * <p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"jwt", "jwt_vc", "jwt_vp", "ldp", "ldp_vc", "ldp_vp", "vc+sd-jwt"})
@Generated("jsonschema2pojo")
public class ClaimFormat {

    @JsonProperty("jwt")
    private GenericFormat jwt;
    @JsonProperty("jwt_vc")
    private GenericFormat jwtVc;
    @JsonProperty("jwt_vp")
    private GenericFormat jwtVp;
    @JsonProperty("ldp")
    private GenericFormat ldp;
    @JsonProperty("ldp_vc")
    private GenericFormat ldpVc;
    @JsonProperty("ldp_vp")
    private GenericFormat ldpVp;
    @JsonProperty("vc+sd-jwt")
    private SdGenericFormat vcSdJwt;

    @JsonProperty("jwt")
    public GenericFormat getJwt() {
        return jwt;
    }

    @JsonProperty("jwt")
    public void setJwt(GenericFormat jwt) {
        this.jwt = jwt;
    }

    @JsonProperty("jwt_vc")
    public GenericFormat getJwtVc() {
        return jwtVc;
    }

    @JsonProperty("jwt_vc")
    public void setJwtVc(GenericFormat jwtVc) {
        this.jwtVc = jwtVc;
    }

    @JsonProperty("jwt_vp")
    public GenericFormat getJwtVp() {
        return jwtVp;
    }

    @JsonProperty("jwt_vp")
    public void setJwtVp(GenericFormat jwtVp) {
        this.jwtVp = jwtVp;
    }

    @JsonProperty("ldp")
    public GenericFormat getLdp() {
        return ldp;
    }

    @JsonProperty("ldp")
    public void setLdp(GenericFormat ldp) {
        this.ldp = ldp;
    }

    @JsonProperty("ldp_vc")
    public GenericFormat getLdpVc() {
        return ldpVc;
    }

    @JsonProperty("ldp_vc")
    public void setLdpVc(GenericFormat ldpVc) {
        this.ldpVc = ldpVc;
    }

    @JsonProperty("ldp_vp")
    public GenericFormat getLdpVp() {
        return ldpVp;
    }

    @JsonProperty("ldp_vp")
    public void setLdpVp(GenericFormat ldpVp) {
        this.ldpVp = ldpVp;
    }

    @JsonProperty("vc+sd-jwt")
    public SdGenericFormat getVcSdJwt() {
        return vcSdJwt;
    }

    @JsonProperty("vc+sd-jwt")
    public void setVcSdJwt(SdGenericFormat vcSdJwt) {
        this.vcSdJwt = vcSdJwt;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(ClaimFormat.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("jwt");
        sb.append('=');
        sb.append(((this.jwt == null) ? "<null>" : this.jwt));
        sb.append(',');
        sb.append("jwtVc");
        sb.append('=');
        sb.append(((this.jwtVc == null) ? "<null>" : this.jwtVc));
        sb.append(',');
        sb.append("jwtVp");
        sb.append('=');
        sb.append(((this.jwtVp == null) ? "<null>" : this.jwtVp));
        sb.append(',');
        sb.append("ldp");
        sb.append('=');
        sb.append(((this.ldp == null) ? "<null>" : this.ldp));
        sb.append(',');
        sb.append("ldpVc");
        sb.append('=');
        sb.append(((this.ldpVc == null) ? "<null>" : this.ldpVc));
        sb.append(',');
        sb.append("ldpVp");
        sb.append('=');
        sb.append(((this.ldpVp == null) ? "<null>" : this.ldpVp));
        sb.append(',');
        sb.append("vcSdJwt");
        sb.append('=');
        sb.append(((this.vcSdJwt == null) ? "<null>" : this.vcSdJwt));
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
        result = ((result * 31) + ((this.ldpVp == null) ? 0 : this.ldpVp.hashCode()));
        result = ((result * 31) + ((this.ldpVc == null) ? 0 : this.ldpVc.hashCode()));
        result = ((result * 31) + ((this.jwt == null) ? 0 : this.jwt.hashCode()));
        result = ((result * 31) + ((this.vcSdJwt == null) ? 0 : this.vcSdJwt.hashCode()));
        result = ((result * 31) + ((this.jwtVc == null) ? 0 : this.jwtVc.hashCode()));
        result = ((result * 31) + ((this.ldp == null) ? 0 : this.ldp.hashCode()));
        result = ((result * 31) + ((this.jwtVp == null) ? 0 : this.jwtVp.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof ClaimFormat) == false) {
            return false;
        }
        ClaimFormat rhs = ((ClaimFormat) other);
        return ((((((((this.ldpVp == rhs.ldpVp) || ((this.ldpVp != null) && this.ldpVp.equals(rhs.ldpVp))) && ((this.ldpVc == rhs.ldpVc) || ((this.ldpVc != null) && this.ldpVc.equals(rhs.ldpVc)))) && ((this.jwt == rhs.jwt) || ((this.jwt != null) && this.jwt.equals(rhs.jwt)))) && ((this.vcSdJwt == rhs.vcSdJwt) || ((this.vcSdJwt != null) && this.vcSdJwt.equals(rhs.vcSdJwt)))) && ((this.jwtVc == rhs.jwtVc) || ((this.jwtVc != null) && this.jwtVc.equals(rhs.jwtVc)))) && ((this.ldp == rhs.ldp) || ((this.ldp != null) && this.ldp.equals(rhs.ldp)))) && ((this.jwtVp == rhs.jwtVp) || ((this.jwtVp != null) && this.jwtVp.equals(rhs.jwtVp))));
    }

}
