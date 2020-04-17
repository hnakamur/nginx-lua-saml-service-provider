#!/usr/bin/env luajit

local lu = require('luaunit')

TestResponse = {}
function TestResponse:testTakeValuesFromResponse()
    local res_xml = [[<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_EXAMPLE_SSO_c49c68da-0f9a-4b33-afb0-0f55e7ecd18b" Version="2.0" IssueInstant="2020-03-17T21:56:15Z" Destination="https://sp.example.com/sso/saml2" InResponseTo="_888e7b875b0b96ff109dbcdd1b969aa0">
  <saml:Issuer>https://idp.example.com/saml2</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference URI="#_EXAMPLE_SSO_c49c68da-0f9a-4b33-afb0-0f55e7ecd18b">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>2gK90e38pGMlubk1XpmwPyqHjt8=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>IYB7XHBn0SWT/XFom1yHY5QB+Gv5xXnX3w2I4GJ4zwgW3Rld1Np67acsazVsYRfU
V55rDAA7iOAtJ7bFSfgLipOUr2S6XYHIt4IZ3FBbHwlUEPit3OMg/11BKGD+yhwP
pRUw3MY+jgYB6JXiobVwhXyvAKR5bO8tovltjB5PrzlTEkmREz65v/09Fjd1cPFg
lN2dThEyMGKx4p04l3tkHanA/8jZ33Tb5gq3z1EDnFBNktEb6RUwY79mxvY1V4xU
GmmOSoVCLfFrXNaHAU9/lAYmZNpesnb5zLFKRWjj6OIisjMjsHsUGqVVqcjfHR4g
QC8H3lsGwlOfX/2yX41vJ5zRMhGtHTnwD8k+1NBLOmt/Gl8QWHFFMEtNENNT0xIS
gNA1MxdnqASSb3O9IUJcJm3uERhZH4z1kEObLi8r3q9OMLdXwFUY2q2i6OR0QBrs
/svz/fQOHsheY3jzwZCSWFs1PPzEnJTcayg+fyRhn+nNMbBROxL4/Tj1Qxc3Z61b
bYTfvo3KF6/Pv51yuj3J/ZX/6Qz+aH3WI7JuHN7puH6yEvb7Ks/Xm0mfo41N6c3u
T7bh4dA+7KK8Wm1ybKCi2FI1ATqFkBK1lmYC+cJJm1KpmlD4DQXxHh3n4FNiKqTI
3y9pO7x+gy1KnuBK0QfXKkgQ+pmnTb9mmzlgBnEnHS0=</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509SubjectName>CN=Example self-signed CA,O=Example self-signed CA organization,ST=Osaka,C=JP</ds:X509SubjectName>
        <ds:X509IssuerSerial>
<ds:X509IssuerName>CN=Example self-signed CA,O=Example self-signed CA organization,ST=Osaka,C=JP</ds:X509IssuerName>
<ds:X509SerialNumber>1</ds:X509SerialNumber>
</ds:X509IssuerSerial>
        <ds:X509Certificate>MIIFlTCCA32gAwIBAgIBATANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJKUDEO
MAwGA1UECAwFT3Nha2ExLDAqBgNVBAoMI0V4YW1wbGUgc2VsZi1zaWduZWQgQ0Eg
b3JnYW5pemF0aW9uMR8wHQYDVQQDDBZFeGFtcGxlIHNlbGYtc2lnbmVkIENBMB4X
DTIwMDMxNjIyMDg1NloXDTMwMDMyNDIyMDg1NlowbDELMAkGA1UEBhMCSlAxDjAM
BgNVBAgMBU9zYWthMSwwKgYDVQQKDCNFeGFtcGxlIHNlbGYtc2lnbmVkIENBIG9y
Z2FuaXphdGlvbjEfMB0GA1UEAwwWRXhhbXBsZSBzZWxmLXNpZ25lZCBDQTCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJnFa8mTw2FB8tm/ud0D/RZ4jOy3
9MTtppdPCFe76bvbkI0DzRysV9g4JghQza2J5HbfqjpJtT8l8fjaZg3LY5+2U0BE
2/UeLusWSpCNxZDv+iOuOgPIpSd2KPWbJFayFZsFJpRMwGfVocNpR08uDSKnt7Ld
KW+wLa/pJEMOCmpCGw3YUUnq3P+MM+Vt4nHJAujD6lbTToFnsiX/kMDdLuDLfNnP
+elb2tjrV7BvwCvMH7VnwV0os1htDW+oBU5KYtcKqORJDEKkEUz5y55CATDCuaDr
RTc3FNLM2tGhHxov9YaCIxZm7KOIBa9LI1mrp7U4s47Gi5vt8ReGwO2evAuEftsh
in52J/ISBC8YpuHHE6+XrQ/Iuhat/cG3b18Iy8Sa61tZK3ERGysE2j7tzPg7E/bu
wNk0Lqlsj4syiJ4Mqj4oiHvggMc/26G7/KzmA0g8ye7OoAgwb4nO+KSRSU9w4S5H
JBKklnwe4dVPDMD2OfA+lss6dOHyPskFsjA64NshAe56Wfy446gXJ+PYRWszrKtd
4CK4UYSUjnOFYSYOfP5gT2Y5Yo27G65JPqAA4hN7buH6X3IE3O2hBfftWg4ITr/7
OHoSSO1JhuTrXVrM4g+IhcFSIcCps/Ldegor6yRAbzjqBvtzPvWazzYuj1MoZVQG
7POKbMDBcexhpFmBAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/
BAQDAgEGMB0GA1UdDgQWBBTeWuzbCWkZZC+IulITIvmZuj8dUzANBgkqhkiG9w0B
AQsFAAOCAgEAXfkAVCV7+4oFNzCZ8E1Ao1EDjVNqiuRkNnmzmHj1JHoqmtf+5wXB
zcN9aO5YtruF8rCBO1t9IV5dj4KpgTC3AC9VyNwJpmT44p985bB+KtVMuLGtEIPm
uqkLliRPYQmfwmw+AhISnyrS73YBplfXcm1fqbj69FgWaokJgr7v+0El+1FxTTbf
AhBHwnblk98Lo1VUFw63Y3dKkLvu3NBVsDNSZlaL4Yp53uWe9Wc2aMmaN8Ey6Ric
sRu2NJhBxmwJlE6CzzeWEO0mBjIV66nIVhYHS7yl7HZGQRuKQcu7NOyaxhrYDmSC
JdcN58W3jxNooL7zhkVmfE1Xziz7WOkz/Qf397rAXyYIWYV8/IJ2tAYL0yw1qNdt
PfGsHhFATFejkWmMMrV5AEoSy+NM7fCnh4YFoFGa2kPcDzbZMuJ12wtrXwO6fEez
LCuc365bWmqh7cr1SXJj+pP0lVeoL5Mbi755k8KXWgpKWhGcC4MmS9A235pPSSx1
dWc+TLNB2X+D6x9oTmzHkdLCfjWSUmGqZ+JyBo755tVJC5iAiSjqvaUEJGNWz2ka
6L0jCIs0JI5cOi6HdQaCZcH3gzGd/JOPUCpr/0SSfCX/xLKtPmby16kHWAdeedGr
ZUZuh1KuSsL4K1kqFxYGZd2vSO8h5COahlVYCxLgX9F6z+7tj1LCms8=</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_a_ac18682e1d51b6e755688f8591f1c40f" Version="2.0" IssueInstant="2020-03-17T21:56:15Z">
    <saml:Issuer>https://idp.example.com/saml2</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:persistent" NameQualifier="sso.example.com" SPNameQualifier="https://sp.example.com/sso">john-doe</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="_888e7b875b0b96ff109dbcdd1b969aa0" NotOnOrAfter="2020-03-17T22:01:15Z" Recipient="https://sp.example.com/sso/saml2"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2020-03-17T21:51:15Z" NotOnOrAfter="2020-03-17T22:01:15Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com/sso</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2020-03-17T21:56:15Z" SessionNotOnOrAfter="2020-03-18T21:56:15Z" SessionIndex="_s_6d3964cd6d26c51949e0208732cf9581">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
        <saml:AttributeValue xsi:type="xs:anyType">john-doe@example.com</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
]]

    local saml_sp_response = require('saml.service_provider.response')
    local sp_resp = saml_sp_response.new(res_xml, {})
    local values = sp_resp:take_values()
    lu.assertEquals(values.name_id, 'john-doe', 'NameID')
    lu.assertEquals(values.request_id, '_888e7b875b0b96ff109dbcdd1b969aa0', 'request ID')
    lu.assertEquals(values.not_on_or_after, '2020-03-17T22:01:15Z', 'request NotOnOrAfter')
    lu.assertEquals(values.session_not_on_or_after, '2020-03-18T21:56:15Z', 'SessionNotOnOrAfter')
    lu.assertEquals(values.attrs['mail'], 'john-doe@example.com', 'mail attribute')
end

os.exit(lu.LuaUnit.run())
