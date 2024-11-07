var expect = require('chai').expect;
const rdsInstanceGeneration = require('./rdsInstanceGeneration');

const describeDBInstances = [
    {
    DBInstanceIdentifier: 'test-1',
    DBInstanceClass: 'db.t1.micro',
    Engine: 'postgres',
    DBInstanceStatus: 'available',
    MasterUsername: 'postgres',
    Endpoint: {
      Address: 'test-1.cscif9l5pu36.us-east-1.rds.amazonaws.com',
      Port: 5432,
      HostedZoneId: 'Z2R2ITUGPM61AM'
    },
    AvailabilityZone: 'us-east-1a',
    DBSubnetGroup: {
      DBSubnetGroupName: 'default-vpc-112223344',
      DBSubnetGroupDescription: 'Created from the Neptune Management Console',
      VpcId: 'vpc-112223344',
      SubnetGroupStatus: 'Complete',
      Subnets: [Array],
      SupportedNetworkTypes: []
    },
    PreferredMaintenanceWindow: 'mon:07:45-mon:08:15',
    PendingModifiedValues: {},
    StorageEncrypted: true,
    DBInstanceArn: 'arn:aws:rds:us-east-1:5566441122:db:test-1',
    TagList: [],
    DBInstanceAutomatedBackupsReplications: [],
    CustomerOwnedIpEnabled: false,
    ActivityStreamStatus: 'stopped',
    BackupTarget: 'region',
    NetworkType: 'IPV4'
  },
    {
    DBInstanceIdentifier: 'test2-1',
    DBInstanceClass: 'db.t3.micro',
    Engine: 'postgres',
    DBInstanceStatus: 'available',
    MasterUsername: 'postgres',
    Endpoint: {
      Address: 'test2-1.cscif9l5pu36.us-east-1.rds.amazonaws.com',
      Port: 5432,
      HostedZoneId: 'Z2R2ITUGPM61AM'
    },
    AvailabilityZone: 'us-east-1a',
    DBSubnetGroup: {
      DBSubnetGroupName: 'default-vpc-112223344',
      DBSubnetGroupDescription: 'Created from the Neptune Management Console',
      VpcId: 'vpc-112223344',
      SubnetGroupStatus: 'Complete',
      Subnets: [Array],
      SupportedNetworkTypes: []
    },
    PreferredMaintenanceWindow: 'mon:07:45-mon:08:15',
    PendingModifiedValues: {},
    StorageEncrypted: true,
    DBInstanceArn: 'arn:aws:rds:us-east-1:5566441122:db:test2-1',
    TagList: [{key: "Key", value: "value"}],
    DBInstanceAutomatedBackupsReplications: [],
    CustomerOwnedIpEnabled: false,
    ActivityStreamStatus: 'stopped',
    BackupTarget: 'region',
    NetworkType: 'IPV4'
  },
];

const createCache = (groups) => {
    return {
        rds:{
            describeDBInstances: {
                'us-east-1': {
                    data: groups,
                    err: null
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        rds:{
            describeDBInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing rds instances'
                    },
                },
            }
        },
    };
};


describe('rdsInstanceGeneration', function () {
    describe('run', function () {
        it('should PASS if RDS Instance is using current generation', function (done) {
            const cache = createCache([describeDBInstances[1]]);
            rdsInstanceGeneration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).includes('RDS instance is using current generation of EC2: ');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if RDS Instance is using older generation', function (done) {
            const cache = createCache([describeDBInstances[0]]);
            rdsInstanceGeneration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).includes('RDS instance is using an older generation of EC2: ');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no RDS Instance found', function (done) {
            const cache = createCache([]);
            rdsInstanceGeneration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).includes('No RDS instances found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNWON unable to describe RDS Instances', function (done) {
            const cache = createErrorCache();
            rdsInstanceGeneration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).includes('Unable to query for RDS instances: ');
                done();
            });
        });

    });
});