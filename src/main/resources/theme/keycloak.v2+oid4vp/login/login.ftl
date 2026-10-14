<#if oid4vp?? && oid4vp.authContext??>
    <#include "login-oid4vp-v2.ftl">
<#else>
    <#include "login-default.ftl">
</#if>
