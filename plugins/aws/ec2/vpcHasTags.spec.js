var expect = require('chai').expect;
var vpcHasTags = require('./vpcHasTags')
const describeVpcs =[
{
    CidrBlock: '10.10.0.0/16',
    DhcpOptionsId: 'dopt-020bdd32klmnb8567f',
    State: 'available',
    VpcId: 'vpc-0e7a0457ff482f4315',
    OwnerId: '10136382434',
    InstanceTenancy: 'default',
    Ipv6CidrBlockAssociationSet: [],
    CidrBlockAssociationSet: [],
    IsDefault: true,
    Tags: []
  }, 
  {
    CidrBlock: '10.10.0.0/16',
    DhcpOptionsId: 'dopt-020bdd32klmnb8567f',
    State: 'available',
    VpcId: 'vpc-0e7a0457ff482f4315',
    OwnerId: '10136382434',
    InstanceTenancy: 'default',
    Ipv6CidrBlockAssociationSet: [],
    CidrBlockAssociationSet: [],
    IsDefault: true,
    Tags: [{key:"key", value:"value"}]
  },
]

const createCache = (vpcs) => {
    return {
        ec2: {
            describeVpcs: {
                'us-east-1': {
                    data: vpcs,
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeVpcs: {
                'us-east-1': {
                    err: {
                        message: 'error describing vpcs'
                    },
                },
            },
        },
    };
};

describe('vpcHasTags', function () {
    describe('run', function () {
        it('should FAIL if VPC does not have tags', function (done) {
            const cache = createCache([describeVpcs[0]]);
            vpcHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if vpc has tags', function (done) {
            const cache = createCache([describeVpcs[1]]);
            vpcHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no vpcs are detected', function (done) {
            const cache = createCache([]);
            vpcHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for VPCs', function (done) {
            const cache = createErrorCache();
            vpcHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
