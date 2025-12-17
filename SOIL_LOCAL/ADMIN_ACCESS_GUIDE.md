# How to Access the Admin Dashboard

## Step 1: Set a User as Super Admin

You need to update a user's role in the database to `super_admin`. Here are two methods:

### Method 1: Using Python SQLite (Recommended)

1. Open a terminal/command prompt in your project directory
2. Run Python and execute these commands:

```python
import sqlite3

# Connect to the database
conn = sqlite3.connect('soilsense_local.db')
c = conn.cursor()

# Set a user as super admin (replace 'your_username' with the actual username)
c.execute("UPDATE users SET role = 'super_admin' WHERE username = ?", ('your_username',))
conn.commit()
conn.close()

print("User set as super admin!")
```

### Method 2: Using SQLite Command Line

1. Open a terminal/command prompt in your project directory
2. Run:
   ```bash
   sqlite3 soilsense_local.db
   ```
3. Then execute:
   ```sql
   UPDATE users SET role = 'super_admin' WHERE username = 'your_username';
   ```
4. Type `.quit` to exit

### Method 3: Using a SQLite GUI Tool

If you have a SQLite GUI tool (like DB Browser for SQLite, DBeaver, etc.):
1. Open `soilsense_local.db` in your tool
2. Execute this SQL:
   ```sql
   UPDATE users SET role = 'super_admin' WHERE username = 'your_username';
   ```

## Step 2: Access the Admin Dashboard

Once a user is set as `super_admin`:

1. **Log in** with that user's credentials
2. **Look for the "Admin" button** in the navigation menu (it will appear in orange/amber color)
3. **Click "Admin"** or go directly to: `http://localhost:5000/admin`

## What You'll See

The admin dashboard shows:
- **Overview Statistics**: Total farmers, active farmers, total sensor readings, total pump events
- **All Farmers List**: A grid of all registered farmers with:
  - Quick stats (pump events, auto/manual counts)
  - Expandable details showing sensor readings, averages, and activity timestamps
  - Full pump events and sensor history tables for each farmer

## Notes

- Only users with `role = 'super_admin'` can access the admin dashboard
- Regular users with `role = 'farmer'` will be redirected to the dashboard if they try to access `/admin`
- The Admin link only appears in the navigation for super-admin users

