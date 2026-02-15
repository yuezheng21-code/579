# PostgreSQL Configuration for Railway

This application now supports both SQLite (for local development) and PostgreSQL (for production on Railway).

## How It Works

The application automatically detects which database to use based on the `DATABASE_URL` environment variable:

- **If `DATABASE_URL` is set**: Uses PostgreSQL
- **If `DATABASE_URL` is not set**: Uses SQLite (local file: `hr_system.db`)

## Setting Up PostgreSQL on Railway

### Step 1: Add PostgreSQL Plugin to Your Railway Project

1. Go to your Railway project dashboard
2. Click "New" → "Database" → "Add PostgreSQL"
3. Railway will automatically create a PostgreSQL database and set the `DATABASE_URL` environment variable

### Step 2: Deploy Your Application

Your application will automatically use the PostgreSQL database when deployed on Railway. No code changes needed!

### Step 3: Verify the Connection

After deployment, you can check the logs to verify that PostgreSQL is being used:
- Look for database initialization logs
- The application will automatically create all necessary tables on first run

## Environment Variables

The following environment variable is used for database configuration:

- `DATABASE_URL`: PostgreSQL connection string (automatically set by Railway)
  - Format: `postgresql://user:password@host:port/database`

## Local Development

For local development, you can continue using SQLite (default) or test with a local PostgreSQL instance:

### Using SQLite (Default)
```bash
# No configuration needed - just run the app
python3 app.py
```

### Using Local PostgreSQL (Optional)
```bash
# Set DATABASE_URL environment variable
export DATABASE_URL="postgresql://user:password@localhost:5432/hr_system"
python3 app.py
```

## Database Features

The application uses database wrappers to ensure compatibility between SQLite and PostgreSQL:

- **Automatic parameter placeholder conversion**: `?` (SQLite) ↔ `%s` (PostgreSQL)
- **Timestamp handling**: `TEXT` with `datetime('now')` (SQLite) ↔ `TIMESTAMP` with `CURRENT_TIMESTAMP` (PostgreSQL)
- **Auto-increment**: `INTEGER PRIMARY KEY AUTOINCREMENT` (SQLite) ↔ `SERIAL PRIMARY KEY` (PostgreSQL)
- **Row factory**: Consistent dict-like access to query results

## Migration Notes

- All existing data in SQLite will need to be migrated manually if you switch to PostgreSQL
- The database schema is identical between SQLite and PostgreSQL
- Consider using a database migration tool if you need to preserve data

## Troubleshooting

### Connection Issues
If you encounter connection issues on Railway:
1. Verify that the PostgreSQL plugin is added to your project
2. Check that `DATABASE_URL` is set in your environment variables
3. Review the deployment logs for error messages

### Schema Issues
If tables are not created:
1. The application automatically creates tables on startup
2. Check logs for any SQL errors
3. Ensure the PostgreSQL user has CREATE TABLE permissions

## Support

For issues specific to:
- **Railway deployment**: Check Railway documentation
- **PostgreSQL**: Check PostgreSQL documentation
- **Application code**: Review `database.py` for database logic
