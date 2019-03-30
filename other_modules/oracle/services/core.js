var bootVolume = require( './core/bootVolume.js' );
var bootVolumeAttachment = require( './core/bootVolumeAttachment.js' );
var consoleHistory = require( './core/consoleHistory.js' );
var cpe = require( './core/cpe.js' );
var crossConnect = require( './core/crossConnect.js' );
var crossConnectGroup = require( './core/crossConnectGroup.js' );
var crossConnectLocation = require( './core/crossConnectLocation.js' );
var crossConnectPortSpeedShape = require( './core/crossConnectPortSpeedShape.js' );
var crossConnectStatus = require( './core/crossConnectStatus.js' );
var dhcpOptions = require( './core/dhcpOptions.js' );
var drg = require( './core/drg.js' );
var drgAttachment = require( './core/drgAttachment.js' );
var fastConnectProviderServices = require( './core/fastConnectProviderServices.js' );
var image = require( './core/image.js' );
var instance = require( './core/instance.js' );
var instanceConsoleConnection = require( './core/instanceConsoleConnection.js' );
var instanceCredential = require( './core/instanceCredential.js' );
var internetGateway = require( './core/internetGateway.js' );
var ipSecConnection = require( './core/ipSecConnection.js' );
var ipSecConnectionDeviceConfig = require( './core/ipSecConnectionDeviceConfig.js' );
var ipSecConnectionDeviceStatus = require( './core/ipSecConnectionDeviceStatus.js' );
var letterOfAuthority = require( './core/letterOfAuthority.js' );
var localPeeringGateway = require( './core/localPeeringGateway.js' );
var peerRegionForRemotePeering = require( './core/peerRegionForRemotePeering.js' );
var privateIp = require( './core/privateIp.js' );
var publicIp = require( './core/publicIp.js' );
var remotePeeringConnection = require( './core/remotePeeringConnection.js' );
var routeTable = require( './core/routeTable.js' );
var securityList = require( './core/securityList.js' );
var service = require( './core/service.js' );
var serviceGateway = require( './core/serviceGateway.js' );
var shape = require( './core/shape.js' );
var subnet = require( './core/subnet.js' );
var vcn = require( './core/vcn.js' );
var virtualCircuit = require( './core/virtualCircuit.js' );
var virtualCircuitBandwidthShape = require( './core/virtualCircuitBandwidthShape.js' );
var virtualCircuitPublicPrefix = require( './core/virtualCircuitPublicPrefix.js' );
var vnic = require( './core/vnic.js' );
var vnicAttachment = require( './core/vnicAttachment.js' );
var volume = require( './core/volume.js' );
var volumeAttachment = require( './core/volumeAttachment.js' );
var volumeBackup = require( './core/volumeBackup.js' );
var volumeBackupPolicy = require( './core/volumeBackupPolicy.js' );
var volumeBackupPolicyAssignment = require( './core/volumeBackupPolicyAssignment.js' );
var volumeGroup = require( './core/volumeGroup.js' );
var volumeGroupBackup = require( './core/volumeGroupBackup.js' );

module.exports = {
    bootVolume: bootVolume,
    bootVolumeAttachment: bootVolumeAttachment,
    consoleHistory: consoleHistory,
    cpe: cpe,
    crossConnect: crossConnect,
    crossConnectGroup: crossConnectGroup,
    crossConnectLocation: crossConnectLocation,
    crossConnectPortSpeedShape: crossConnectPortSpeedShape,
    crossConnectStatus: crossConnectStatus,
    dhcpOptions: dhcpOptions,
    drg: drg,
    drgAttachment: drgAttachment,
    fastConnectProviderServices: fastConnectProviderServices,
    image: image,
    instance: instance,
    instanceConsoleConnection: instanceConsoleConnection,
    instanceCredential: instanceCredential,
    internetGateway: internetGateway,
    ipSecConnection: ipSecConnection,
    ipSecConnectionDeviceConfig: ipSecConnectionDeviceConfig,
    ipSecConnectionDeviceStatus: ipSecConnectionDeviceStatus,
    letterOfAuthority: letterOfAuthority,
    localPeeringGateway: localPeeringGateway,
    peerRegionForRemotePeering: peerRegionForRemotePeering,
    privateIp: privateIp,
    publicIp: publicIp,
    remotePeeringConnection: remotePeeringConnection,
    routeTable: routeTable,
    securityList: securityList,
    service: service,
    serviceGateway: serviceGateway,
    shape: shape,
    subnet: subnet,
    vcn: vcn,
    virtualCircuit: virtualCircuit,
    virtualCircuitBandwidthShape: virtualCircuitBandwidthShape,
    virtualCircuitPublicPrefix: virtualCircuitPublicPrefix,
    vnic: vnic,
    vnicAttachment: vnicAttachment,
    volume: volume,
    volumeAttachment: volumeAttachment,
    volumeBackup: volumeBackup,
    volumeBackupPolicy: volumeBackupPolicy,
    volumeBackupPolicyAssignment: volumeBackupPolicyAssignment,
    volumeGroup: volumeGroup,
    volumeGroupBackup: volumeGroupBackup
}