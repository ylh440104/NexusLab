import { SqliteDatabase } from '@nexuslab/sqlite';

/** Opens asynchronously with the shared WAL, durability and busy-timeout defaults. */
export function openSqliteDb(dbPath: string): SqliteDatabase {
    return new SqliteDatabase(dbPath);
}
