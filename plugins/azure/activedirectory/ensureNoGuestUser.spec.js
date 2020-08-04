var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./ensureNoGuestUser');

const createCache = (err, data) => {
    return {
        users: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('ensureNoGuestUser', function() {
    describe('run', function() {
        it('should give passing result if no users', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing users found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        });

        it('should give failing result if guest users exist', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The user is a guest user');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "objectId": "ba01a7d0-2fef-4a44-adf7-55fc1e04300b",
                        "objectType": "User",
                        "usageLocation": "US",
                        "userType": "Member",
                        "accountEnabled": true,
                        "displayName": "Michael",
                        "userPrincipalName": "Michael@aol.com",
                        "mailNickname": "cariel",
                        "mail": "Michael@aol.com",
                        "signInNames": [],
                        "location": "global"
                    },
                    {
                        "objectId": "0965a9ab-ee57-4fa2-a6af-3c754f3692c1",
                        "objectType": "User",
                        "givenName": "Carlos",
                        "surname": "Martinez",
                        "userType": "Guest",
                        "accountEnabled": true,
                        "displayName": "carlos",
                        "userPrincipalName": "carlosgmail.com#EXT#@gmail.onmicrosoft.com",
                        "mailNickname": "gioroddev_gmail.com#EXT#",
                        "mail": "gioroddev@gmail.com",
                        "signInNames": [],
                        "location": "global"
                    },
                    {
                        "objectId": "d1309f70-3c63-48a4-b9e0-a18535ad8da7 ",
                        "objectType": "User",
                        "userType": "Member",
                        "accountEnabled": true,
                        "displayName": "Mike",
                        "userPrincipalName": "Mike@aol.com",
                        "mailNickname": "giovanni",
                        "signInNames": [],
                        "location": "global"
                    },
                    {
                        "objectId": "2cf0a439-b225-472a-81de-7bd44afa3924",
                        "objectType": "User",
                        "userType": "Member",
                        "accountEnabled": true,
                        "displayName": "josh",
                        "userPrincipalName": "josh@gmail.com",
                        "mailNickname": "josh",
                        "mail": "josh@gmail.com",
                        "signInNames": [],
                        "location": "global"
                    },
                    {
                        "objectId": "3e6c6dbc-38e9-48f6-b724-76aa95bdfd06",
                        "objectType": "User",
                        "usageLocation": "US",
                        "givenName": "Mark",
                        "surname": "Flores",
                        "userType": "Member",
                        "accountEnabled": true,
                        "displayName": "Mark Flores",
                        "userPrincipalName": "mark@hotmail.com",
                        "mailNickname": "matt",
                        "mail": "mark@hotmail.com",
                        "signInNames": [],
                        "location": "global"
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if there are no guest users', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The subscription does not have any guest users');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "objectId": "ba01a7d0-2fef-4a44-adf7-55fc1e04300b",
                        "objectType": "User",
                        "usageLocation": "US",
                        "userType": "Member",
                        "accountEnabled": true,
                        "displayName": "Michael",
                        "userPrincipalName": "Michael@aol.com",
                        "mailNickname": "cariel",
                        "mail": "Michael@aol.com",
                        "signInNames": [],
                        "location": "global"
                    },
                    {
                        "objectId": "d1309f70-3c63-48a4-b9e0-a18535ad8da7 ",
                        "objectType": "User",
                        "userType": "Member",
                        "accountEnabled": true,
                        "displayName": "Mike",
                        "userPrincipalName": "Mike@aol.com",
                        "mailNickname": "giovanni",
                        "signInNames": [],
                        "location": "global"
                    },
                    {
                        "objectId": "2cf0a439-b225-472a-81de-7bd44afa3924",
                        "objectType": "User",
                        "userType": "Member",
                        "accountEnabled": true,
                        "displayName": "josh",
                        "userPrincipalName": "josh@gmail.com",
                        "mailNickname": "josh",
                        "mail": "josh@gmail.com",
                        "signInNames": [],
                        "location": "global"
                    },
                    {
                        "objectId": "3e6c6dbc-38e9-48f6-b724-76aa95bdfd06",
                        "objectType": "User",
                        "usageLocation": "US",
                        "givenName": "Mark",
                        "surname": "Flores",
                        "userType": "Member",
                        "accountEnabled": true,
                        "displayName": "Mark Flores",
                        "userPrincipalName": "mark@hotmail.com",
                        "mailNickname": "matt",
                        "mail": "mark@hotmail.com",
                        "signInNames": [],
                        "location": "global"
                    }
                ]
            );

            auth.run(cache, {}, callback);
        })
    })
})