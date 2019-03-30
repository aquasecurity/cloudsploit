var cloudAccount = require( './myServices/cloudAccount.js' );
var cloudAccounts = require( './myServices/cloudAccounts' );
var operation = require( './myServices/operation' );
var operations = require( './myServices/operations' );
var purchaseEntitlement = require( './myServices/purchaseEntitlement' );
var purchaseEntitlements = require( './myServices/purchaseEntitlements' );
var seExadataSecurityGroup = require( './myServices/seExadataSecurityGroup' );
var seExadataSecurityGroups = require( './myServices/seExadataSecurityGroups' );
var serviceDefinition = require( './myServices/serviceDefinition' );
var serviceDefinitions = require( './myServices/serviceDefinitions' );
var serviceEntitlement = require( './myServices/serviceEntitlement' );
var serviceEntitlements = require( './myServices/serviceEntitlements' );
var serviceInstance = require( './myServices/serviceInstance' );
var serviceInstances = require( './myServices/serviceInstances' );
var seServiceConfiguration = require( './myServices/seServiceConfiguration' );
var seServiceConfigurations = require( './myServices/seServiceConfigurations' );
var siExadataSecurityGroupAssignment = require( './myServices/siExadataSecurityGroupAssignment' );
var siExadataSecurityGroupAssignments = require( './myServices/siExadataSecurityGroupAssignments' );
var siServiceConfiguration = require( './myServices/siServiceConfiguration' );
var siServiceConfigurations = require( './myServices/siServiceConfigurations' );

module.exports = {
      cloudAccount : cloudAccount,
      cloudAccounts : cloudAccounts,
      operation: operation,
      operations: operations,
      purchaseEntitlement: purchaseEntitlement,
      purchaseEntitlements: purchaseEntitlements,
      seExadataSecurityGroup: seExadataSecurityGroup,
      seExadataSecurityGroups: seExadataSecurityGroups,
      serviceDefinition: serviceDefinition,
      serviceDefinitions: serviceDefinitions,
      serviceEntitlement: serviceEntitlement,
      serviceEntitlements: serviceEntitlements,
      serviceInstance: serviceInstance,
      serviceInstances: serviceInstances,
      seServiceConfiguration: seServiceConfiguration,
      seServiceConfigurations: seServiceConfigurations,
      siExadataSecurityGroupAssignment: siExadataSecurityGroupAssignment,
      siExadataSecurityGroupAssignments: siExadataSecurityGroupAssignments,
      siServiceConfiguration: siServiceConfiguration,
      siServiceConfigurations: siServiceConfigurations
}