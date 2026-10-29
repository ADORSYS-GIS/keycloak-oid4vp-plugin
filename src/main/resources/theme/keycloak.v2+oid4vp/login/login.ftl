<#if oid4vpWalletHandoff??>
    <#include "login-oid4vp-handoff.ftl">
<#elseif oid4vp?? && oid4vp.authContext??>
    <#include "login-oid4vp-v2.ftl">
<#else>
    <#include "login-default.ftl">
</#if>
