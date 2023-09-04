const expect = require('chai').expect;
const sshKeysRotated = require('./sshKeysRotated');

var warnDate = new Date();
warnDate.setMonth(warnDate.getMonth() - 6);
var passDate = new Date();
passDate.setMonth(passDate.getMonth() - 2);
var failDate = new Date();
failDate.setMonth(failDate.getMonth() - 12);

const listUsers = [
    {
        'Path': '/',
        'UserName': 'cloudsploit',
        'UserId': 'AIDARPGOCGXSSUH7TNLM4',
        'Arn': 'arn:aws:iam::000011111:user/cloudsploit',
        'CreateDate': '2021-12-12T13:15:54+00:00'
    },
    { 
        'Path': '/',
        'UserName': 'testUser',
        'UserId': 'AIDARPGOCGXSUSX63OQEM',
        'Arn': 'arn:aws:iam::0000111111112:user/testUser',
        'CreateDate': '2022-10-10T11:41:15+00:00'
    }
];

var listSSHPublicKeys = [
    {
        'SSHPublicKeys': [
            {
                'UserName': 'cloudsploit',
                'SSHPublicKeyId': 'APKASZ433I6EO2NEWLNK',
                'Status': 'Active',
                'UploadDate': passDate
            }
        ]
    },{
        'SSHPublicKeys': [
            {
                'UserName': 'testUser',
                'SSHPublicKeyId': 'APKASZ433I6ELJJ6BQT5',
                'Status': 'Active',
                'UploadDate': warnDate
            }
        ]
    },{
        'SSHPublicKeys': [
            {
                'UserName': 'testUser',
                'SSHPublicKeyId': 'APKASZ433I6ELJJ6BQT5',
                'Status': 'Active',
                'UploadDate': failDate
            }
        ]
    },{
        'SSHPublicKeys': [
            {}
        ]
}];


const createCache = (listUsers, listSSHPublicKeys) => {
    var userName = (listUsers && listUsers.length) ? listUsers[0].UserName : null; 
    return {
        iam: {
            listUsers: {
                'us-east-1': {
                    data: listUsers,
                    err: null
                },
            },
            listSSHPublicKeys: {
                'us-east-1': {
                    [userName]:{   
                        data: listSSHPublicKeys,
                        err: null    
                    }              
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        iam: {
            listUsers: {
                'us-east-1': {
                    err: {
                        message: 'Unable to query for Users:'
                    },
                },
            }
        }
    };
};


describe('sshKeysRotated', function() {
    describe('run', function() {
        it('should PASS if SSH key is less than 180 days old', function(done) {
            const cache = createCache([listUsers[0]],listSSHPublicKeys[0]);
            sshKeysRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].resource).to.equal('arn:aws:iam::000011111:user/cloudsploit');
                done();
            });
        });

        it('should WARN if SSH key was created more than 180 days ago', function(done) {
            const cache = createCache([listUsers[1]],listSSHPublicKeys[1]);
            const settings = { ssh_keys_rotated_warn: 150 };
            sshKeysRotated.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });
        
        it('should FAIL if SSH key was created more than 360 days ago', function(done) {
            const cache = createCache([listUsers[1]],listSSHPublicKeys[2]);
            const settings = { ssh_keys_rotated_fail: 300 };
            sshKeysRotated.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no SSH keys found', function(done) {
            const cache = createCache([listUsers[1]],listSSHPublicKeys[3]);
            sshKeysRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SSH keys found');
                done();
            });
        });

        it('should UNKNOWN if unable to query for users', function(done) {
            const cache = createErrorCache();
            sshKeysRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Users:');
                done();
            });
        });

        it('should UNKNOWN if unable to query for SSH Keys', function(done) {
            const cache = createCache([listUsers[0]]);
            sshKeysRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SSH Keys:');
                done();
            });
        });       
    });
});
