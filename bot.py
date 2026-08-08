import os

from telegram import Update
from telegram.ext import (
    Application,
    MessageHandler,
    ContextTypes,
    filters
)

TOKEN = os.getenv("BOT_TOKEN")

async def check_message(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):
    message = update.effective_message
    
    if not message:
        return
        
    text = message.text or ""
    
    print(f"Received: {text}")
    
def main():
    if not TOKEN:
        raise RuntimeError("BOT_TOKEN is not configured")
       
    app = Application.builder().token(TOKEN).build()
    
    app.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            check_message
        )
    )
    
    print("Bot is running...")
    
    app.run_polling()
    
if __name__ == "__main__"
    main()