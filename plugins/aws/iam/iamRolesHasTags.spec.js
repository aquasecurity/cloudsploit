const expect = require('chai').expect;
const iamRolesHasTags = require('./iamRolesHasTags.js');

const listUsers = [
    {
        RoleName: 'test1',
        Arn: 'arn:aws:iam::000111222333:service-role/test1',
        Tags: []
    }, 
    {
        RoleName: 'test2',
        UserId: 'AIDAYE32SRU545SJ5O6AI',
        Arn: 'arn:aws:iam::000111222333:service-role/test2',
        Tags: [{"Name" : "tag", "Value": "val"}]
    }   
];

const createCache = (listRoles) => {
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    data: listRoles,
                    err: null
                },
            },
        }
    };
};

const createErrorCache = () => {
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    err: {
                        message: 'error listing IAM Roles'
                    },
                },
            },
        },
    };
};

describe('iamRolesHasTags', function () {
    describe('run', function () {
        it('should give passing result if iam role has tags', function (done) {
            const cache = createCache([listUsers[1]]);
            iamRolesHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should give failing result if iam role has no tags', function (done) {
            const cache = createCache([listUsers[0]]);
            iamRolesHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        it('should give unknown result if error in lsiting Roles', function (done) {
            const cache = createErrorCache();
            iamRolesHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should give passing result if no iam role found', function (done) {
            const cache = createCache([]);
            iamRolesHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

    });
});