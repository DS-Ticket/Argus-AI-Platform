import sys
from interface import ChatbotInterface
from data_connector import DataConnector

# initialize bot
bot = ChatbotInterface(DataConnector())

def main():
    print("RUNNING SCRIPT") 
    if len(sys.argv) < 2:
        print("No input provided")
        return

    user_input = " ".join(sys.argv[1:])
    
    try:
        response = bot.respond(user_input)
        print(response)
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()