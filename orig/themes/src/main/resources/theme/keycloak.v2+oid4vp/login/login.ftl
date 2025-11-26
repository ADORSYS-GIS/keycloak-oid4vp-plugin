<#if oid4vp?? && oid4vp.authContext??>
    <#include "login-oid4vp.ftl">
<#else>
    <#include "login-default.ftl">
</#if>
