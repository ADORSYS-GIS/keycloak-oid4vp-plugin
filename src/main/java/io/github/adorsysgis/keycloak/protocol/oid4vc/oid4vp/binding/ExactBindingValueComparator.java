package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding;

import org.keycloak.utils.StringUtil;

/**
 * Default, schema-neutral comparator performing a strict, case-sensitive equality check. A blank
 * presented value never matches, preserving the historical binding-rule semantics.
 */
public class ExactBindingValueComparator implements BindingValueComparator {

    @Override
    public boolean matches(String presentedValue, String expectedValue) {
        if (StringUtil.isBlank(presentedValue)) {
            return false;
        }
        return presentedValue.equals(expectedValue);
    }
}
