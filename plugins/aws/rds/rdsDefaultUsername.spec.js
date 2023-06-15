var expect = require('chai').expect;
var rdsDefaultUserName = require('./rdsDefaultUsername');

const describeDBInstances=[
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
        StorageEncrypted: true,
        DBInstanceArn: 'arn:aws:rds:us-east-1:5566441122:db:test-1',
       
    },
    {
        DBInstanceIdentifier: 'test-2',
        DBInstanceClass: 'db.t3.micro',
        Engine: 'postgres',
        DBInstanceStatus: 'available',
        MasterUsername: 'Fatima',
        Endpoint: {
          Address: 'test-1.cscif9l5pu36.us-east-1.rds.amazonaws.com',
          Port: 5432,
          HostedZoneId: 'Z2R2ITUGPM61AM'
        },
        AvailabilityZone: 'us-east-1a',
        StorageEncrypted: true,
        DBInstanceArn: 'arn:aws:rds:us-east-1:5566441122:db:test-2',
       
    },
    {
        DBInstanceIdentifier: 'test-3',
        DBInstanceClass: 'db.t3.micro',
        Engine: 'mysql',
        DBInstanceStatus: 'available',
        MasterUsername: 'admin',
        Endpoint: {
          Address: 'test-1.cscif9l5pu36.us-east-1.rds.amazonaws.com',
          Port: 5432,
          HostedZoneId: 'Z2R2ITUGPM61AM'
        },
        AvailabilityZone: 'us-east-1a',
        StorageEncrypted: true,
        DBInstanceArn: 'arn:aws:rds:us-east-1:5566441122:db:test-3',
       
    }
]
const createCache=(data)=>{
  return{
        rds:{
            describeDBInstances:{
                'us-east-1':{
                    data:data,
                    err:null
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

describe('rdsDefaultUserName',function(){
    describe('run',function(){

        it('should give pass if the rds instance username is not default',function(done){
            const cache=createCache([describeDBInstances[1]]);
            rdsDefaultUserName.run(cache,{},(err,results)=> {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).includes('RDS instance does not have a default master username');
                expect(results[0].region).to.equal('us-east-1');
                done();
             });
        });
     
       it('should fail if the username is default of the rds instace',function(done){
           const cache=createCache([describeDBInstances[0]]);
           rdsDefaultUserName.run(cache,{},(err,results)=>{
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).includes('RDS instance has a default master username');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
       });

    it('should PASS if no RDS Instance found', function (done) {
        const cache = createCache([]);
        rdsDefaultUserName.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).includes('No RDS instances found');
            expect(results[0].region).to.equal('us-east-1');
            done();
        });
    });

    it('should UNKNWON unable to describe RDS Instances', function (done) {
        const cache = createErrorCache();
        rdsDefaultUserName.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].message).includes('Unable to query for RDS instances: ');
            expect(results[0].region).to.equal('us-east-1');
            done();
            });
        });
    });
});
