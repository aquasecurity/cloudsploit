var expect = require('chai').expect;
var plugin = require('./okeSecurityGroups');

const clusters = [
    {
        id: 'ocid1.cluster.oc1',
        name: 'cluster1',
        compartmentId: 'ocid1.tenancy.oc1.aaa111111',
        endpointConfig: {
          subnetId: 'ocid1.subnet.oc1.aaaaa',
          isPublicIpEnabled: false
        },
        vcnId: 'ocid1.vcn.oc1.vcn-1',
        kubernetesVersion: 'v1.22.5'
      }
]
const securityRules = [
    {
        direction: 'INGRESS',
        id: '1111',
        isStateless: false,
        isValid: true,
        protocol: '6',
        source: 'ocid1.networksecuritygroup.oc1.nsg-1',
        sourceType: 'NETWORK_SECURITY_GROUP',
        tcpOptions: {
          destinationPortRange: { max: 443, min: 443 },
          sourcePortRange: { max: 443, min: 443 }
        },
        timeCreated: '2022-06-26T22:08:03.792Z',
        networkSecurityGroups: 'ocid1.networksecuritygroup.oc1.nsg-1'
      },
      {
        direction: 'INGRESS',
        id: '111',
        isStateless: false,
        isValid: true,
        protocol: 'all',
        source: 'ocid1.networksecuritygroup.oc1.nsg-1',
        sourceType: 'NETWORK_SECURITY_GROUP',
        timeCreated: '2022-06-26T22:09:22.114Z',
        networkSecurityGroups: 'ocid1.networksecuritygroup.oc1.nsg-1'
      }
    
];

const securityGroups = [
    {
        compartmentId: 'ocid1.tenancy.oc1.11111',
        displayName: 'firstgroup',
        freeformTags: {},
        id: 'ocid1.networksecuritygroup.oc1.nsg-1',
        lifecycleState: 'AVAILABLE',
        timeCreated: '2022-01-09T13:03:47.999Z',
        vcnId: 'ocid1.vcn.oc1.vcn-1'
    }      
]

const createCache = (data, err, securityGroupData, securityGroupErr, securityRuleData, securityRuleErr) => {
    return {
        regionSubscription: {
            "list": {
                "us-ashburn-1": {
                    "data": [
                        {
                            "regionKey": "IAD",
                            "regionName": "us-ashburn-1",
                            "status": "READY",
                            "isHomeRegion": true
                        },
                        {
                            "regionKey": "LHR",
                            "regionName": "uk-london-1",
                            "status": "READY",
                            "isHomeRegion": false
                        },
                        {
                            "regionKey": "PHX",
                            "regionName": "us-phoenix-1",
                            "status": "READY",
                            "isHomeRegion": false
                        }
                    ]
                }
            }
        },
        cluster: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        },
        networkSecurityGroup: {
            list: {
                'us-ashburn-1': {
                    err: securityGroupErr,
                    data: securityGroupData
                }
            }
        },
        securityRule: {
            list: {
                'us-ashburn-1': {
                    err: securityRuleErr,
                    data: securityRuleData
                }
            }
        }
    }
};

describe('okeSecurityGroups', function () {
    describe('run', function () {

        it('should give unknown result if a cluster error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for OKE clusters')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                ['error'],
                securityGroups,
                null,
                securityRules,
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no oke clusters are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No OKE clusters found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [],
                null,
                null,
                securityGroups,
                null,
                securityRules,
                null
            
            );

            plugin.run(cache, {}, callback);
        })


        it('should give unknown result if a security rule error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for security rules')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                clusters,
                null,
                securityGroups,
                null,
                null,
                ['error']
            );

            plugin.run(cache, {}, callback);
        })

        it('should give unknown result if a security group error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for network security groups')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                clusters,
                null,
                null,
                ['error'],
                securityRules,
                null
            );

            plugin.run(cache, {}, callback);
        })
        
        it('should give failing result if oke cluster security groups allow acces on unnecessary port ranges', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('OKE cluster security groups allow additional access on unnecessary ports')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                clusters,
                null,
                securityGroups,
                null,
                securityRules,
                null
            
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if oke cluster security groups do not allow acces on unnecessary port ranges', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('do not allow additional access on unnecessary ports')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                clusters,
                null,
                securityGroups,
                null,
                [securityRules[0]],
                null
            
            );

            plugin.run(cache, {}, callback);
        })


    })
})