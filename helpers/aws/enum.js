const encryptionLevelMap = {
    none: 0,
    sse: 1,
    awskms: 2,
    awscmk: 3,
    externalcmk: 4,
    cloudhsm: 5,
    0: 'none',
    1: 'sse',
    2: 'awskms',
    3: 'awscmk',
    4: 'externalcmk',
    5: 'cloudhsm',
};

module.exports = {
    encryptionLevelMap,
};