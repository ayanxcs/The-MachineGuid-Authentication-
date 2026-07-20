import os
import re
import json
import shutil
import asyncio
from pathlib import Path
from datetime import datetime, timedelta
import discord
from discord.ext import commands, tasks

# Discord Bot Configuration - Set your Discord bot token and ID values here
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "YOUR_DISCORD_BOT_TOKEN_HERE")
OWNER_ID = int(os.getenv("DISCORD_OWNER_ID", "1426790747516047492"))
DEFAULT_SERVER_ID = int(os.getenv("DEFAULT_SERVER_ID", "1320592077997998162"))

DATA_DIR = Path("database")
BACKUP_DIR = Path("backups")
USERS_FILE = DATA_DIR / "users.json"
HWID_FILE = DATA_DIR / "hwid.json"
LOGS_FILE = DATA_DIR / "logs.json"
BOT_DATA_FILE = DATA_DIR / "bot_data.json"
LOG_QUEUE_FILE = DATA_DIR / "log_queue.json"

DATA_DIR.mkdir(exist_ok=True)
BACKUP_DIR.mkdir(exist_ok=True)

intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

def read_json(file_path):
    try:
        if not file_path.exists():
            if file_path == BOT_DATA_FILE:
                return {
                    "authorized_servers": [DEFAULT_SERVER_ID],
                    "resellers": [],
                    "server_logins": {},
                    "free_mode": {
                        "enabled": False,
                        "exe_name": "",
                        "expire_time": None
                    },
                    "logs_channel": None,
                    "reset_cooldowns": {}
                }
            return {"users": [], "hwids": [], "logs": []}.get(file_path.stem, {})
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return {}

def write_json(file_path, data):
    try:
        if file_path.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = BACKUP_DIR / f"{file_path.stem}_backup_{timestamp}.json"
            shutil.copy(file_path, backup_path)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error writing {file_path}: {e}")
        return False

def add_log(event, username=None, hwid=None, details=None):
    try:
        logs_data = read_json(LOGS_FILE)
        log_entry = {
            "id": os.urandom(16).hex(),
            "event": event,
            "username": username,
            "hwid": hwid,
            "date": datetime.now().isoformat(),
            "details": details
        }
        logs_data.setdefault("logs", []).insert(0, log_entry)
        if len(logs_data["logs"]) > 1000:
            logs_data["logs"] = logs_data["logs"][:1000]
        write_json(LOGS_FILE, logs_data)
        
        bot_data = read_json(BOT_DATA_FILE)
        logs_channel_id = bot_data.get("logs_channel")
        if logs_channel_id:
            asyncio.create_task(send_log_to_discord(logs_channel_id, log_entry))
    except Exception as e:
        print(f"Error adding log: {e}")

async def send_log_to_discord(channel_id, log_entry):
    try:
        channel = bot.get_channel(int(channel_id))
        if channel:
            embed = discord.Embed(title=f"Log: {log_entry['event']}", color=0xffffff)
            if log_entry.get('username'):
                embed.add_field(name="Username", value=log_entry['username'], inline=True)
            if log_entry.get('hwid'):
                embed.add_field(name="HWID", value=log_entry['hwid'], inline=True)
            if log_entry.get('details'):
                embed.add_field(name="Details", value=log_entry['details'], inline=False)
            embed.set_footer(text=log_entry['date'])
            await channel.send(embed=embed)
    except Exception as e:
        print(f"Error sending log to discord: {e}")

def create_embed(title, description, color=0xffffff):
    return discord.Embed(title=title, description=description, color=color)

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(embed=create_embed("Error", f"Missing required argument: {error.param.name}"))
    elif isinstance(error, commands.CheckFailure):
        pass
    else:
        add_log("BOT_ERROR", details=str(error)[:200])
        await ctx.send(embed=create_embed("Error", "An internal error occurred. Please contact the administrator."))

def sanitize_input(text):
    if not text:
        return ""
    return re.sub(r'[@#`*_<>\x00-\x1F\x7F]', '', text).strip()

def is_owner():
    async def predicate(ctx):
        return ctx.author.id == OWNER_ID
    return commands.check(predicate)

def is_authorized():
    async def predicate(ctx):
        if ctx.author.id == OWNER_ID:
            return True
        bot_data = read_json(BOT_DATA_FILE)
        if ctx.author.id in bot_data.get("resellers", []):
            return True
        await ctx.send(embed=create_embed("Unauthorized", "Only Authorized Officials Can Use Bot Command"))
        return False
    return commands.check(predicate)

def validate_server_user(guild_id):
    bot_data = read_json(BOT_DATA_FILE)
    username = bot_data.get("server_logins", {}).get(str(guild_id))
    
    if not username:
        return False, "No user logged in on this server. Please use !login first.", None
        
    users_data = read_json(USERS_FILE)
    user = next((u for u in users_data.get('users', []) if u['username'] == username), None)
    
    if not user:
        return False, f"Logged in user '{username}' not found in database.", username
        
    today = datetime.now().date()
    expire_date = datetime.strptime(user['expire_date'], "%Y-%m-%d").date()
    
    if today > expire_date:
        return False, f"User Key '{username}' is Expired.", username
        
    return True, "Valid", username

@bot.event
async def on_ready():
    print(f'Bot is ready as {bot.user}')
    bot_data = read_json(BOT_DATA_FILE)
    if DEFAULT_SERVER_ID not in bot_data.get("authorized_servers", []):
        bot_data.setdefault("authorized_servers", []).append(DEFAULT_SERVER_ID)
        write_json(BOT_DATA_FILE, bot_data)
        
    for guild in bot.guilds:
        if guild.id not in bot_data.get("authorized_servers", []):
            print(f"Leaving unauthorized server: {guild.name} ({guild.id})")
            await guild.leave()
            
    if not poll_logs.is_running():
        poll_logs.start()

@tasks.loop(seconds=5.0)
async def poll_logs():
    if not LOG_QUEUE_FILE.exists():
        return
        
    try:
        with open(LOG_QUEUE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        queue = data.get("queue", [])
        if not queue:
            return
            
        bot_data = read_json(BOT_DATA_FILE)
        logs_channel_id = bot_data.get("logs_channel")
        
        if logs_channel_id:
            channel = bot.get_channel(int(logs_channel_id))
            if channel:
                for log_entry in queue:
                    embed = discord.Embed(title=f"Log: {log_entry.get('event', 'UNKNOWN')}", color=0xffffff)
                    if log_entry.get('username'):
                        embed.add_field(name="Username", value=log_entry['username'], inline=True)
                    if log_entry.get('hwid'):
                        embed.add_field(name="HWID", value=log_entry['hwid'], inline=True)
                    if log_entry.get('details'):
                        embed.add_field(name="Details", value=str(log_entry['details'])[:1024], inline=False)
                    embed.set_footer(text=log_entry.get('date', datetime.now().isoformat()))
                    await channel.send(embed=embed)
                    
        with open(LOG_QUEUE_FILE, 'w', encoding='utf-8') as f:
            json.dump({"queue": []}, f)
            
    except Exception as e:
        print(f"Error polling logs: {e}")

@bot.event
async def on_guild_join(guild):
    bot_data = read_json(BOT_DATA_FILE)
    if guild.id not in bot_data.get("authorized_servers", []):
        print(f"Leaving unauthorized server: {guild.name} ({guild.id})")
        await guild.leave()

@bot.command()
@is_owner()
async def add_server(ctx, server_id: int):
    bot_data = read_json(BOT_DATA_FILE)
    if server_id not in bot_data.setdefault("authorized_servers", []):
        bot_data["authorized_servers"].append(server_id)
        write_json(BOT_DATA_FILE, bot_data)
        await ctx.send(embed=create_embed("Success", f"Added server ID {server_id} to authorized list."))
    else:
        await ctx.send(embed=create_embed("Info", "Server is already authorized."))

@bot.command()
@is_owner()
async def remove_server(ctx, server_id: int):
    bot_data = read_json(BOT_DATA_FILE)
    if server_id in bot_data.get("authorized_servers", []):
        bot_data["authorized_servers"].remove(server_id)
        write_json(BOT_DATA_FILE, bot_data)
        await ctx.send(embed=create_embed("Success", f"Removed server ID {server_id} from authorized list."))
        guild = bot.get_guild(server_id)
        if guild:
            await guild.leave()
    else:
        await ctx.send(embed=create_embed("Info", "Server is not in the authorized list."))

@bot.command()
@is_owner()
async def reseller(ctx, action: str = None, user: discord.User = None):
    if not action or not user:
        await ctx.send(embed=create_embed("Error", "Usage: !reseller add @user OR !reseller remove @user"))
        return
        
    bot_data = read_json(BOT_DATA_FILE)
    resellers = bot_data.setdefault("resellers", [])
    
    if action.lower() == "add":
        if user.id not in resellers:
            resellers.append(user.id)
            write_json(BOT_DATA_FILE, bot_data)
            await ctx.send(embed=create_embed("Success", f"Added {user.mention} as a reseller."))
        else:
            await ctx.send(embed=create_embed("Info", f"{user.mention} is already a reseller."))
            
    elif action.lower() == "remove":
        if user.id in resellers:
            resellers.remove(user.id)
            write_json(BOT_DATA_FILE, bot_data)
            await ctx.send(embed=create_embed("Success", f"Removed {user.mention} from resellers."))
        else:
            await ctx.send(embed=create_embed("Info", f"{user.mention} is not a reseller."))
            
    else:
        await ctx.send(embed=create_embed("Error", "Invalid action. Use 'add' or 'remove'."))

@bot.command()
@is_owner()
async def logs(ctx, arg: str):
    if arg.lower() == "set":
        bot_data = read_json(BOT_DATA_FILE)
        bot_data["logs_channel"] = ctx.channel.id
        write_json(BOT_DATA_FILE, bot_data)
        await ctx.send(embed=create_embed("Success", f"Logs channel set to {ctx.channel.mention}. Incoming logs are now active."))
    elif arg.lower() == "off":
        bot_data = read_json(BOT_DATA_FILE)
        if "logs_channel" in bot_data:
            bot_data["logs_channel"] = None
            write_json(BOT_DATA_FILE, bot_data)
            await ctx.send(embed=create_embed("Success", "Incoming logs have been disabled."))
        else:
            await ctx.send(embed=create_embed("Info", "Logs are already disabled."))
    else:
        await ctx.send(embed=create_embed("Error", "Invalid argument. Usage: !logs set OR !logs off"))

@bot.command()
@is_authorized()
async def login(ctx, username: str):
    username = sanitize_input(username).lower()
    users_data = read_json(USERS_FILE)
    user = next((u for u in users_data.get('users', []) if u['username'] == username), None)
    
    if not user:
        await ctx.send(embed=create_embed("Failed", "Login failed: User not found in database."))
        return
        
    today = datetime.now().date()
    expire_date = datetime.strptime(user['expire_date'], "%Y-%m-%d").date()
    
    if today > expire_date:
        await ctx.send(embed=create_embed("Failed", "Login failed: User account is expired."))
        return
        
    bot_data = read_json(BOT_DATA_FILE)
    server_logins = bot_data.setdefault("server_logins", {})
    
    for s_id, logged_user in server_logins.items():
        if logged_user == username and s_id != str(ctx.guild.id):
            await ctx.send(embed=create_embed("Failed", f"Login failed: User '{username}' is already linked to another Discord server."))
            return
            
    server_logins[str(ctx.guild.id)] = username
    write_json(BOT_DATA_FILE, bot_data)
    
    await ctx.send(embed=create_embed("Success", f"Successfully Logged in to {username}"))
    add_log("BOT_LOGIN", username=username, details=f"Logged in via bot in server {ctx.guild.id} by {ctx.author.id}")

@bot.command()
async def free(ctx, arg1: str = None, *, arg2: str = None):
    if not arg1:
        await ctx.send(embed=create_embed("Error", "Missing argument. Usage: !free enable <exe>, !free disable, or !free <hwid>"))
        return

    bot_data = read_json(BOT_DATA_FILE)
    is_owner_or_reseller = ctx.author.id == OWNER_ID or ctx.author.id in bot_data.get("resellers", [])

    if arg1.lower() == "enable":
        if not is_owner_or_reseller:
            await ctx.send(embed=create_embed("Unauthorized", "Only Authorized Officials Can Use Bot Command"))
            return
        if not arg2:
            await ctx.send(embed=create_embed("Error", "Please provide the name of the executable."))
            return
            
        exe_name = sanitize_input(arg2)
        expire_time = (datetime.now() + timedelta(hours=24)).isoformat()
        bot_data["free_mode"] = {
            "enabled": True,
            "exe_name": exe_name,
            "expire_time": expire_time
        }
        write_json(BOT_DATA_FILE, bot_data)
        await ctx.send(embed=create_embed("Free Mode", f"Free mode enabled for 24 hours. Executable: {exe_name}"))
        add_log("BOT_COMMAND", details=f"!free enable {exe_name} used by {ctx.author.id} in {ctx.guild.id}")
        
    elif arg1.lower() == "disable":
        if not is_owner_or_reseller:
            await ctx.send(embed=create_embed("Unauthorized", "Only Authorized Officials Can Use Bot Command"))
            return
        bot_data["free_mode"]["enabled"] = False
        write_json(BOT_DATA_FILE, bot_data)
        
        hwid_data = read_json(HWID_FILE)
        original_count = len(hwid_data.get("hwids", []))
        hwid_data["hwids"] = [h for h in hwid_data.get("hwids", []) if not h.get("is_free")]
        removed_count = original_count - len(hwid_data["hwids"])
        write_json(HWID_FILE, hwid_data)
        
        await ctx.send(embed=create_embed("Free Mode", f"Free mode disabled immediately. Removed {removed_count} free HWIDs."))
        add_log("BOT_COMMAND", details=f"!free disable used by {ctx.author.id} in {ctx.guild.id}")

    else:
        hwid = sanitize_input(arg1)
        free_mode = bot_data.get("free_mode", {})
        
        if not free_mode.get("enabled", False):
            await ctx.send(embed=create_embed("Error", "Free mode is currently disabled."))
            return
            
        expire_time_str = free_mode.get("expire_time")
        if not expire_time_str:
            return
            
        expire_time = datetime.fromisoformat(expire_time_str)
        if datetime.now() > expire_time:
            bot_data["free_mode"]["enabled"] = False
            write_json(BOT_DATA_FILE, bot_data)
            await ctx.send(embed=create_embed("Error", "Free mode has expired."))
            return
            
        is_valid, msg, username = validate_server_user(ctx.guild.id)
        if not is_valid:
            await ctx.send(embed=create_embed("Error", msg))
            return
            
        hwid_data = read_json(HWID_FILE)
        if any(h.get("hwid") == hwid for h in hwid_data.get("hwids", [])):
            await ctx.send(embed=create_embed("Error", "HWID is already registered."))
            return
            
        exe_name = free_mode.get("exe_name", "FREE_EXE")
        
        new_hwid = {
            "username": username,
            "hwid": hwid,
            "exe_name": exe_name,
            "added_at": datetime.now().date().isoformat(),
            "expire_date": expire_time.date().isoformat(),
            "exact_expire_time": expire_time.isoformat(),
            "status": "active",
            "is_free": True
        }
        
        hwid_data.setdefault("hwids", []).append(new_hwid)
        write_json(HWID_FILE, hwid_data)
        
        await ctx.send(embed=create_embed("Success", f"Free access claimed! HWID registered for {username} until {expire_time.strftime('%Y-%m-%d %H:%M:%S')}"))
        add_log("HWID_ADDED_FREE", username=username, hwid=hwid, details=f"Exe: {exe_name}, Expire: {expire_time.isoformat()}")

@bot.command()
async def help(ctx):
    bot_data = read_json(BOT_DATA_FILE)
    free_mode = bot_data.get("free_mode", {})
    
    is_auth = ctx.author.id == OWNER_ID or ctx.author.id in bot_data.get("resellers", [])
    is_free = free_mode.get("enabled", False)
    
    if is_free and free_mode.get("expire_time"):
        expire_time = datetime.fromisoformat(free_mode["expire_time"])
        if datetime.now() > expire_time:
            is_free = False
            
    if is_auth or is_free:
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            bat_path = os.path.join(base_dir, "HWID.bat")
            
            if os.path.exists(bat_path):
                await ctx.author.send(
                    embed=create_embed("Help", "Run The bat file on your system to get your HWID"),
                    file=discord.File(bat_path)
                )
                await ctx.send(embed=create_embed("Success", "Help sent to your DM."))
            else:
                await ctx.send(embed=create_embed("Error", f"HWID script not found on the server at: {bat_path}"))
        except:
            await ctx.send(embed=create_embed("Error", "Could not send DM. Please enable direct messages."))
    else:
        await ctx.send(embed=create_embed("Unauthorized", "Only Authorized Officials Can Use Bot Command"))

@bot.command()
@is_authorized()
async def status(ctx):
    bot_data = read_json(BOT_DATA_FILE)
    hwid_data = read_json(HWID_FILE)
    
    is_valid, user_msg, username = validate_server_user(ctx.guild.id)
    
    free_mode = bot_data.get("free_mode", {})
    is_free_enabled = free_mode.get("enabled", False)
    
    free_hwids_count = sum(1 for h in hwid_data.get("hwids", []) if h.get("is_free"))
    user_hwids_count = sum(1 for h in hwid_data.get("hwids", []) if h.get("username") == username) if username else 0
    
    embed = discord.Embed(title="System Status", color=0xffffff)
    embed.add_field(name="Free Mode", value="Enabled" if is_free_enabled else "Disabled", inline=False)
    if is_free_enabled:
        embed.add_field(name="Free Mode Expiry", value=free_mode.get("expire_time"), inline=False)
    embed.add_field(name="Total Free HWIDs Claimed", value=str(free_hwids_count), inline=False)
    
    if username:
        status_val = "Active" if is_valid else f"Issues: {user_msg}"
        embed.add_field(name=f"Logged in as {username} ({status_val})", value=f"Total HWIDs: {user_hwids_count}", inline=False)
    else:
        embed.add_field(name="Login Status", value="Not logged in on this server", inline=False)
        
    await ctx.send(embed=embed)
    add_log("BOT_COMMAND", details=f"!status used by {ctx.author.id} in {ctx.guild.id}")

@bot.command()
@is_authorized()
async def data(ctx):
    is_valid, msg, username = validate_server_user(ctx.guild.id)
    if not is_valid:
        await ctx.send(embed=create_embed("Error", msg))
        return
        
    hwid_data = read_json(HWID_FILE)
    user_hwids = [h for h in hwid_data.get("hwids", []) if h.get("username") == username]
    
    if not user_hwids:
        await ctx.send(embed=create_embed("Info", "No HWIDs found for the logged in user."))
        return
        
    content = f"Data for user: {username}\n\n"
    for h in user_hwids:
        content += f"HWID: {h.get('hwid')}\nExecutable: {h.get('exe_name')}\nAdded: {h.get('added_at')}\nExpires: {h.get('expire_date')}\nStatus: {h.get('status')}\n"
        if h.get('is_free'):
            content += "Type: FREE CLAIM\n"
        content += "-" * 20 + "\n"
        
    file_path = f"data_{username}.txt"
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
        
    try:
        await ctx.author.send(embed=create_embed("Data Export", f"Here is the data for {username}"), file=discord.File(file_path))
        await ctx.send(embed=create_embed("Success", "Data has been sent to your DM."))
    except:
        await ctx.send(embed=create_embed("Error", "Could not send DM. Please enable direct messages."))
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)
    add_log("BOT_COMMAND", details=f"!data used by {ctx.author.id} in {ctx.guild.id}")

@bot.command()
@is_authorized()
async def report(ctx, *, issue: str):
    issue = sanitize_input(issue)
    owner = bot.get_user(OWNER_ID)
    if owner:
        embed = discord.Embed(title="New Report", color=0xffffff)
        embed.add_field(name="Reporter", value=f"{ctx.author} ({ctx.author.id})", inline=False)
        embed.add_field(name="Server", value=f"{ctx.guild.name} ({ctx.guild.id})", inline=False)
        embed.add_field(name="Time", value=datetime.now().isoformat(), inline=False)
        embed.add_field(name="Issue", value=issue, inline=False)
        try:
            await owner.send(embed=embed)
            await ctx.send(embed=create_embed("Success", "Report sent to the owner."))
        except:
            await ctx.send(embed=create_embed("Error", "Failed to send report to owner."))
    add_log("BOT_COMMAND", details=f"!report used by {ctx.author.id} in {ctx.guild.id}")

@bot.command()
@is_authorized()
async def reset(ctx, arg: str):
    if arg.lower() != "hwid":
        return
        
    is_valid, msg, username = validate_server_user(ctx.guild.id)
    if not is_valid:
        await ctx.send(embed=create_embed("Error", msg))
        return
        
    bot_data = read_json(BOT_DATA_FILE)
    last_reset = bot_data.setdefault("reset_cooldowns", {}).get(username)
    if last_reset:
        last_reset_time = datetime.fromisoformat(last_reset)
        if datetime.now() < last_reset_time + timedelta(hours=24):
            remaining = (last_reset_time + timedelta(hours=24) - datetime.now())
            hours, remainder = divmod(remaining.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            await ctx.send(embed=create_embed("Cooldown", f"You can reset HWID again in {hours}h {minutes}m."))
            return
            
    users_data = read_json(USERS_FILE)
    user = next((u for u in users_data.get('users', []) if u['username'] == username), None)
    
    if user:
        user['device_fingerprint'] = None
        user['first_login_ip'] = None
        user['first_login_ua'] = None
        write_json(USERS_FILE, users_data)
        
        bot_data["reset_cooldowns"][username] = datetime.now().isoformat()
        write_json(BOT_DATA_FILE, bot_data)
        
        await ctx.send(embed=create_embed("Success", f"Device lock reset for {username}."))
        add_log("BOT_COMMAND", username=username, details=f"!reset hwid used by {ctx.author.id} in {ctx.guild.id}")
    else:
        await ctx.send(embed=create_embed("Error", "User not found in database."))

def main():
    if BOT_TOKEN and BOT_TOKEN != "YOUR_DISCORD_BOT_TOKEN_HERE":
        bot.run(BOT_TOKEN)
    else:
        print("Discord bot token not configured. Set DISCORD_BOT_TOKEN environment variable or update BOT_TOKEN.")

if __name__ == "__main__":
    main()
