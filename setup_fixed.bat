@echo off
echo 🔧 Fixing PyTorch and installing dependencies...

:: Activate your environment
call chatbot_env\Scripts\activate

:: Install compatible versions
pip install torch==2.3.0 torchvision==0.18.0 torchaudio==2.3.0
pip install sentence-transformers==2.7.0
pip install langchain-huggingface==0.1.0

:: Install other requirements
pip install streamlit langchain langchain-community langchain-core langchain-groq
pip install langgraph chromadb pypdf python-dotenv
pip install SpeechRecognition streamlit-mic-recorder pydub

echo ✅ Setup complete! Run: streamlit run main.py
pause