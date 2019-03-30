var availabilityDomain = require( './iam/availabilityDomain.js' );
var apiKey = require( './iam/apiKey.js' );
var authToken = require( './iam/authToken.js' );
var compartment = require( './iam/compartment.js' );
var customerSecretKey = require( './iam/customerSecretKey.js' );
var customerSecretKeySummary = require( './iam/customerSecretKeySummary.js' );
var dynamicGroup = require( './iam/dynamicGroup.js' );
var faultDomain = require( './iam/faultDomain.js' );
var identityProvider = require( './iam/identityProvider.js' );
var idpGroupMapping = require( './iam/idpGroupMapping.js' );
var policy = require( './iam/policy.js' );
var region = require( './iam/region.js' );
var regionSubscription = require( './iam/regionSubscription.js' );
var smtpCredential = require( './iam/smtpCredential.js' );
var smtpCredentialSummary = require( './iam/smtpCredentialSummary.js' );
var swiftPassword = require( './iam/swiftPassword.js' );
var tag = require( './iam/tag.js' );
var tagNamespace = require( './iam/tagNamespace.js' );
var tagNamespaceSummary = require( './iam/tagNamespaceSummary.js' );
var tagSummary = require( './iam/tagSummary.js' );
var tenancy = require( './iam/tenancy.js' );
var uiPassword = require( './iam/uiPassword.js' );
var user = require( './iam/user.js' );
var userGroupMembership = require( './iam/userGroupMembership.js' );

module.exports = {
    availabilityDomain: availabilityDomain,
    apiKey: apiKey,
    authToken: authToken,
    compartment: compartment,
    customerSecretKey: customerSecretKey,
    customerSecretKeySummary: customerSecretKeySummary,
    dynamicGroup: dynamicGroup,
    faultDomain: faultDomain,
    identityProvider: identityProvider,
    idpGroupMapping: idpGroupMapping,
    policy: policy,
    region: region,
    regionSubscription: regionSubscription,
    smtpCredential: smtpCredential,
    smtpCredentialSummary: smtpCredentialSummary,
    swiftPassword: swiftPassword,
    tag: tag,
    tagNamespace: tagNamespace,
    tagNamespaceSummary: tagNamespaceSummary,
    tagSummary: tagSummary,
    tenancy: tenancy,
    uiPassword: uiPassword,
    user: user,
    userGroupMembership: userGroupMembership
}