import os

from telegram import Update

from telegram.ext import (

    Application,

    MessageHandler,

    ContextTypes,

    filters,

)

TOKEN = os.getenv("BOT_TOKEN")

RENDER_URL = os.getenv("RENDER_URL")

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

BANNED_WORDS = [

    "คำต้องห้าม1",

    "คำต้องห้าม2",

    "คำต้องห้าม3",

]

async def is_admin(

    update: Update,

    context: ContextTypes.DEFAULT_TYPE

):

    message = update.effective_message

    if not message or not message.from_user:

        return False

    member = await context.bot.get_chat_member(

        message.chat_id,

        message.from_user.id

    )

    return member.status in (

        "administrator",

        "creator"

    )

async def check_message(

    update: Update,

    context: ContextTypes.DEFAULT_TYPE

):

    message = update.effective_message

    if not message or not message.from_user:

        return

    if await is_admin(update, context):

        return

    text = message.text or ""

    for word in BANNED_WORDS:

        if word.lower() in text.lower():

            try:

                await message.delete()

                print(

                    f"Deleted message from "

                    f"{message.from_user.id}"

                )

            except Exception as error:

                print(

                    f"Delete error: {error}"

                )

            break

def main():

    if not TOKEN:

        raise RuntimeError(

            "BOT_TOKEN is not configured"

        )

    if not RENDER_URL:

        raise RuntimeError(

            "RENDER_URL is not configured"

        )

    if not WEBHOOK_SECRET:

        raise RuntimeError(

            "WEBHOOK_SECRET is not configured"

        )

    port = int(os.getenv("PORT", "10000"))

    application = (

        Application

        .builder()

        .token(TOKEN)

        .build()

    )

    application.add_handler(

        MessageHandler(

            filters.TEXT & ~filters.COMMAND,

            check_message

        )

    )

    webhook_url = (

        f"{RENDER_URL}/telegram"

    )

    print(

        f"Starting webhook on port {port}"

    )

    application.run_webhook(

        listen="0.0.0.0",

        port=port,

        url_path="telegram",

        webhook_url=webhook_url,

        secret_token=WEBHOOK_SECRET,

    )

if __name__ == "__main__":

    main()