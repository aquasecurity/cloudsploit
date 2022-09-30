var expect = require('chai').expect;
const rdsInstanceHasTags = require('./rdsInstanceHasTags');

const describeDBInstances = [
    {
    DBInstanceIdentifier: 'test-1',
    DBInstanceClass: 'db.t3.micro',
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


describe('rdsInstanceHasTags', function () {
    describe('run', function () {
        it('should PASS if RDS Instance has Tags', function (done) {
            const cache = createCache([describeDBInstances[1]]);
            rdsInstanceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if RDS Instance does not Tags', function (done) {
            const cache = createCache([describeDBInstances[0]]);
            rdsInstanceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no RDS Instance found', function (done) {
            const cache = createCache([]);
            rdsInstanceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNWON unable to describe RDS Instances', function (done) {
            const cache = createErrorCache();
            rdsInstanceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

    });
});