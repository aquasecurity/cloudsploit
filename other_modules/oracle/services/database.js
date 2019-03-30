var autonomousDatabase = require( './database/autonomousDatabase.js' );
var autonomousDataWarehouse = require( './database/autonomousDataWarehouse.js' );
var autonomousDatabaseBackup = require( './database/autonomousDatabaseBackup.js' );
var autonomousDataWarehouseBackup = require( './database/autonomousDataWarehouseBackup.js' );
var database = require( './database/database.js' );
var backup = require( './database/backup.js' );
var dataGuardAssociations = require( './database/dataGuardAssociation.js' );
var dbHome = require( './database/dbHome.js' );
var dbSystem = require( './database/dbSystem.js' );
var dbSystemShapeSummary = require( './database/dbSystemShapeSummary.js' );
var dbVersionSummary = require( './database/dbVersionSummary.js' );
var patch = require( './database/patch.js' );
var patchHistoryEntry = require( './database/patchHistoryEntry.js' );

module.exports = {
    autonomousDatabase: autonomousDatabase,
    autonomousDataWarehouse: autonomousDataWarehouse,
    autonomousDatabaseBackup: autonomousDatabaseBackup,
    autonomousDataWarehouseBackup: autonomousDataWarehouseBackup,
    database: database,
    backup: backup,
    dataGuardAssociations: dataGuardAssociations,
    dbHome: dbHome,
    dbSystem: dbSystem,
    dbSystemShapeSummary: dbSystemShapeSummary,
    dbVersionSummary: dbVersionSummary,
    patch: patch,
    patchHistoryEntry: patchHistoryEntry
}