var expect = require('chai').expect;
const vpcPeeringLeastAccessRoutes = require('./vpcPeeringLeastAccessRoutes');

const describeVpcPeeringConnections = [
    {
        VpcPeeringConnectionId: 'pcx-abc123',
        RequesterVpcInfo: {
            VpcId: 'vpc-local',
            CidrBlock: '10.0.0.0/16'
        },
        AccepterVpcInfo: {
            VpcId: 'vpc-peer',
            CidrBlock: '10.1.0.0/16'
        }
    }
];

const describeRouteTables = [
    {
        RouteTableId: 'rtb-1',
        VpcId: 'vpc-local',
        Routes: [
            {
                DestinationCidrBlock: '0.0.0.0/0',
                GatewayId: 'igw-123'
            }
        ]
    },
    {
        RouteTableId: 'rtb-1',
        VpcId: 'vpc-local',
        Routes: [
            {
                DestinationCidrBlock: '10.1.0.0/16',
                VpcPeeringConnectionId: 'pcx-abc123'
            }
        ]
    },
    {
        RouteTableId: 'rtb-1',
        VpcId: 'vpc-local',
        Routes: [
            {
                DestinationCidrBlock: '10.1.2.0/24',
                VpcPeeringConnectionId: 'pcx-abc123'
            }
        ]
    },
    {
        RouteTableId: 'rtb-1',
        VpcId: 'vpc-local',
        Routes: [
            {
                DestinationCidrBlock: '10.1.2.5/32',
                VpcPeeringConnectionId: 'pcx-abc123'
            }
        ]
    }
];

const createCache = (routeTables, peerings) => {
    return {
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: '111122223333'
                }
            }
        },
        ec2: {
            describeRouteTables: {
                'us-east-1': {
                    data: routeTables
                },
            },
            describeVpcPeeringConnections: {
                'us-east-1': {
                    data: peerings
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeRouteTables: {
                'us-east-1': {
                    err: {
                        message: 'error describing route tables'
                    },
                },
            },
            describeVpcPeeringConnections: {
                'us-east-1': {
                    data: [],
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeRouteTables: {
                'us-east-1': null,
            },
        },
    };
};

describe('vpcPeeringLeastAccessRoutes', function () {
    describe('run', function () {
        it('should PASS when no VPC peering routes exist', function (done) {
            const cache = createCache([describeRouteTables[0]], describeVpcPeeringConnections);

            vpcPeeringLeastAccessRoutes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL when peering route uses full peer VPC CIDR', function (done) {
            const cache = createCache([describeRouteTables[1]], describeVpcPeeringConnections);

            vpcPeeringLeastAccessRoutes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS when peering route is more specific than peer VPC CIDR', function (done) {
            const cache = createCache([describeRouteTables[2]], describeVpcPeeringConnections);

            vpcPeeringLeastAccessRoutes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS when peering route targets a single host', function (done) {
            const cache = createCache([describeRouteTables[3]], describeVpcPeeringConnections);

            vpcPeeringLeastAccessRoutes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no route tables found', function (done) {
            const cache = createCache([], describeVpcPeeringConnections);

            vpcPeeringLeastAccessRoutes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for route tables', function (done) {
            const cache = createErrorCache();

            vpcPeeringLeastAccessRoutes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if describe route tables response not found', function (done) {
            const cache = createNullCache();

            vpcPeeringLeastAccessRoutes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
