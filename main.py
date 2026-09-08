import os
import uuid
import tempfile
import sqlite3
import io
import time
import hashlib
import hmac
import warnings
from typing import TypedDict, Annotated, List, Optional, Any
from datetime import datetime
from sqlite3 import Error

import streamlit as st

print("🚀 [Step 1] Streamlit imported", flush=True)

# ─── MUST be the very first Streamlit command ───
st.set_page_config(
    page_title="AI Operating System",
    page_icon="✨",
    layout="wide",
    initial_sidebar_state="expanded"
)
print("🚀 [Step 2] Page config set", flush=True)

from dotenv import load_dotenv
from langgraph.graph import StateGraph, add_messages, START, END
from langchain_groq import ChatGroq

# Voice recognition imports
import speech_recognition as sr
from streamlit_mic_recorder import mic_recorder
print("🚀 [Step 3] Imports completed", flush=True)

# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning)

# Load environment variables
load_dotenv()

# DATABASE SETUP WITH USER AUTHENTICATION

def get_db_path():
    db_path = os.getenv("DB_PATH", "chatbot.db")
    dir_name = os.path.dirname(db_path)
    if dir_name:
        try:
            os.makedirs(dir_name, exist_ok=True)
        except Exception:
            return "chatbot.db"
    return db_path

def get_db_connection():
    """Create a new database connection per request (thread-safe)."""
    db_path = get_db_path()
    try:
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn
    except Exception:
        conn = sqlite3.connect("chatbot.db", check_same_thread=False)
        return conn

def init_database():
    """Initialize SQLite database with user authentication tables"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            full_name TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')

    # Sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')

    # Chats table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chats (
            chat_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            message_type TEXT,
            content TEXT,
            domain TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')

    # Documents table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            doc_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            file_name TEXT,
            file_type TEXT,
            file_size INTEGER,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')

    conn.commit()
    conn.close()

# Initialize database tables on startup
print("🚀 [Step 4] Initializing database tables...", flush=True)
init_database()
print("🚀 [Step 4] Database tables ready!", flush=True)

# AUTHENTICATION UTILITIES

class AuthManager:
    """Handle user authentication and session management"""

    @staticmethod
    def hash_password(password, salt=None):
        if salt is None:
            salt = os.urandom(32).hex()

        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()

        return password_hash, salt

    @staticmethod
    def verify_password(password, stored_hash, salt):
        password_hash, _ = AuthManager.hash_password(password, salt)
        return hmac.compare_digest(password_hash, stored_hash)

    @staticmethod
    def create_user(username, email, password, full_name=""):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                return False, "Username or email already exists"

            user_id = str(uuid.uuid4())
            password_hash, salt = AuthManager.hash_password(password)

            cursor.execute('''
                INSERT INTO users (user_id, username, email, password_hash, salt, full_name)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, username, email, password_hash, salt, full_name))

            conn.commit()
            return True, "User created successfully"
        except Error as e:
            return False, f"Database error: {str(e)}"
        finally:
            conn.close()

    @staticmethod
    def authenticate_user(username, password):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
            user = cursor.fetchone()

            if not user:
                return None, "Invalid username or password"

            columns = [description[0] for description in cursor.description]
            user_dict = dict(zip(columns, user))

            if AuthManager.verify_password(password, user_dict['password_hash'], user_dict['salt']):
                cursor.execute('''
                    UPDATE users SET last_login = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                ''', (user_dict['user_id'],))
                conn.commit()
                return user_dict, "Login successful"

            return None, "Invalid username or password"
        except Error as e:
            return None, f"Database error: {str(e)}"
        finally:
            conn.close()

    @staticmethod
    def create_session(user_id, ip_address="", user_agent=""):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            session_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO sessions (session_id, user_id, ip_address, user_agent)
                VALUES (?, ?, ?, ?)
            ''', (session_id, user_id, ip_address, user_agent))
            conn.commit()
            return session_id
        except Error as e:
            print(f"Session creation error: {e}")
            return None
        finally:
            conn.close()

    @staticmethod
    def end_session(session_id):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions SET is_active = 0
                WHERE session_id = ?
            ''', (session_id,))
            conn.commit()
            return True
        except Error as e:
            print(f"Session end error: {e}")
            return False
        finally:
            conn.close()

    @staticmethod
    def get_user_chats(user_id, limit=50):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT message_type, content, domain, timestamp
                FROM chats
                WHERE user_id = ?
                ORDER BY timestamp ASC
                LIMIT ?
            ''', (user_id, limit))
            return cursor.fetchall()
        except Error as e:
            print(f"Error fetching chats: {e}")
            return []
        finally:
            conn.close()

# LOGIN UI COMPONENTS

def login_ui():
    if 'auth_mode' not in st.session_state:
        st.session_state.auth_mode = "login"
    
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        * {
            font-family: 'Inter', sans-serif;
        }
        
        .auth-title {
            text-align: center;
            font-size: 2.2rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 700;
        }
        
        .auth-subtitle {
            text-align: center;
            color: #94a3b8;
            margin-bottom: 2rem;
            font-size: 0.95rem;
        }
        
        [data-testid="stForm"] {
            background: rgba(255,255,255,0.04) !important;
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.12) !important;
            border-radius: 24px !important;
            padding: 2.5rem !important;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4) !important;
        }
        
        .stTextInput > div > div > input {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 12px 16px;
            color: white;
        }
        
        .stTextInput > div > div > input:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 2px rgba(102,126,234,0.2);
        }
        
        .stButton button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 12px;
            padding: 10px 20px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .stButton button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(102,126,234,0.4);
        }
    </style>
    """, unsafe_allow_html=True)
    
    st.write("")
    st.write("")
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        if st.session_state.auth_mode == "login":
            st.markdown('<h2 class="auth-title">Welcome Back</h2>', unsafe_allow_html=True)
            st.markdown('<p class="auth-subtitle">Sign in to continue your AI journey</p>', unsafe_allow_html=True)
            
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                
                col_a, col_b = st.columns(2)
                with col_a:
                    submit = st.form_submit_button("Sign In", use_container_width=True)
                with col_b:
                    if st.form_submit_button("Create Account", use_container_width=True):
                        st.session_state.auth_mode = "signup"
                        st.rerun()
                
                if submit:
                    if username and password:
                        user, message = AuthManager.authenticate_user(username, password)
                        if user:
                            session_id = AuthManager.create_session(user['user_id'], "local", "streamlit_app")
                            st.session_state.authenticated = True
                            st.session_state.user = user
                            st.session_state.session_id = session_id
                            st.session_state.user_id = user['user_id']
                            st.session_state.messages = []
                            old_chats = AuthManager.get_user_chats(user['user_id'])
                            for msg_type, content, domain, timestamp in old_chats:
                                st.session_state.messages.append((msg_type, content))
                            st.success("✅ Login successful!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")
                    else:
                        st.warning("⚠️ Please enter username and password")
        
        else:
            st.markdown('<h2 class="auth-title">Join the Future</h2>', unsafe_allow_html=True)
            st.markdown('<p class="auth-subtitle">Create your account and start exploring AI</p>', unsafe_allow_html=True)
            
            with st.form("signup_form"):
                full_name = st.text_input("Full Name", placeholder="Enter your full name")
                username = st.text_input("Username", placeholder="Choose a username")
                email = st.text_input("Email", placeholder="Enter your email")
                password = st.text_input("Password", type="password", placeholder="Choose a password")
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm your password")
                
                col_a, col_b = st.columns(2)
                with col_a:
                    submit = st.form_submit_button("Sign Up", use_container_width=True)
                with col_b:
                    if st.form_submit_button("Back to Login", use_container_width=True):
                        st.session_state.auth_mode = "login"
                        st.rerun()
                
                if submit:
                    if not all([full_name, username, email, password, confirm_password]):
                        st.warning("⚠️ Please fill all fields")
                    elif password != confirm_password:
                        st.error("❌ Passwords do not match")
                    elif len(password) < 6:
                        st.warning("⚠️ Password must be at least 6 characters")
                    else:
                        success, message = AuthManager.create_user(username, email, password, full_name)
                        if success:
                            st.success("✅ Account created! Please login.")
                            st.session_state.auth_mode = "login"
                            time.sleep(2)
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")

# ENHANCED CHAT STATE

class State(TypedDict):
    messages: Annotated[List, add_messages]
    domain: str
    session_id: str
    user_id: Optional[str]
    retrieved_docs: List[Any]
    requires_rag: bool

# IMAGE PROCESSOR CLASS WITH CROSS-QUESTION SUPPORT

class ImageProcessor:
    def __init__(self):
        """Initialize ViT-GPT2 for image captioning (no API needed).
        Disabled by default on cloud deployments (torch is ~2.5GB).
        Set ENABLE_IMAGE_MODEL=true to enable."""
        self.available = False
        if os.getenv("ENABLE_IMAGE_MODEL", "false").lower() == "true":
            try:
                from transformers import VisionEncoderDecoderModel, ViTImageProcessor, AutoTokenizer
                self.model = VisionEncoderDecoderModel.from_pretrained(
                    "nlpconnect/vit-gpt2-image-captioning"
                )
                self.feature_extractor = ViTImageProcessor.from_pretrained(
                    "nlpconnect/vit-gpt2-image-captioning"
                )
                self.tokenizer = AutoTokenizer.from_pretrained(
                    "nlpconnect/vit-gpt2-image-captioning"
                )
                self.available = True
            except Exception as e:
                print(f"Image model not loaded: {str(e)}")

    def describe_image(self, image_file, max_length=30):
        """Generate description of image"""
        if not self.available:
            return "⚠️ Image model not available. Set ENABLE_IMAGE_MODEL=true and install: pip install transformers torch torchvision Pillow"

        try:
            from PIL import Image
            # Open and convert image
            if hasattr(image_file, 'read'):
                image = Image.open(image_file).convert('RGB')
            else:
                image = Image.open(io.BytesIO(image_file)).convert('RGB')

            # Process image
            pixel_values = self.feature_extractor(
                images=[image],
                return_tensors="pt"
            ).pixel_values

            # Generate caption
            output_ids = self.model.generate(
                pixel_values,
                max_length=max_length,
                num_beams=4,
                early_stopping=True
            )

            description = self.tokenizer.decode(output_ids[0], skip_special_tokens=True)

            return f"🖼️ **Image Description:** {description}"

        except Exception as e:
            return f"❌ Error analyzing image: {str(e)}"

    def ask_question_about_image(self, image_file, question):
        """Answer specific questions about an image"""
        if not self.available:
            return "⚠️ Image model not available"

        try:
            # Get base description with more detail
            base_desc = self.describe_image(image_file, max_length=50)

            # Use the description to answer specific question
            response = f"**Question:** {question}\n\nBased on the image analysis: {base_desc}"

            return response

        except Exception as e:
            return f"❌ Error: {str(e)}"

# CHATBOT SYSTEM CLASS

class ChatbotSystem:
    def __init__(self):
        # Initialize LLM
        groq_api_key = os.getenv("GROQ_API_KEY") or os.getenv("groq_api_key")
        if not groq_api_key:
            print("❌ GROQ_API_KEY not found", flush=True)
            self.llm = None
        else:
            model_name = os.getenv("GROQ_MODEL") or os.getenv("GROQ_ MODEL") or "openai/gpt-oss-20b"
            print(f"🤖 Initializing ChatGroq with model: {model_name}", flush=True)
            self.llm = ChatGroq(
                model=model_name,
                groq_api_key=groq_api_key,
                temperature=0.7
            )
        
        # Lazy embeddings & vector store
        self._embeddings = None
        self._vector_store = None
        
        # Text splitter
        try:
            from langchain_text_splitters import RecursiveCharacterTextSplitter
        except ImportError:
            try:
                from langchain.text_splitter import RecursiveCharacterTextSplitter
            except ImportError:
                RecursiveCharacterTextSplitter = None
        
        if RecursiveCharacterTextSplitter:
            self.text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=500,
                chunk_overlap=50,
                separators=["\n\n", "\n", " ", ""]
            )
        else:
            self.text_splitter = None
        
        # Available domains
        self.domains = {
            "general": "General knowledge conversation",
            "education": "Educational content assistance",
            "healthcare": "Health information guidance",
            "finance": "Financial advice management",
            "technology": "Tech support and programming"
        }
        
        # Track processed files
        self.processed_files = set()

    @property
    def embeddings(self):
        if self._embeddings is None:
            try:
                try:
                    from langchain_huggingface import HuggingFaceEmbeddings
                except ImportError:
                    from langchain_community.embeddings import HuggingFaceEmbeddings

                emb_model = os.getenv("SENTENCE_TRANSFORMER", "all-MiniLM-L6-v2")
                if not emb_model.startswith("sentence-transformers/") and "/" not in emb_model:
                    emb_model = f"sentence-transformers/{emb_model}"
                self._embeddings = HuggingFaceEmbeddings(
                    model_name=emb_model,
                    model_kwargs={'device': 'cpu'},
                    encode_kwargs={'normalize_embeddings': True}
                )
            except Exception as e:
                print(f"⚠️ Embeddings error: {e}")
                self._embeddings = None
        return self._embeddings

    @embeddings.setter
    def embeddings(self, val):
        self._embeddings = val

    @property
    def vector_store(self):
        if self._vector_store is None:
            try:
                from langchain_community.vectorstores import Chroma
                if self.embeddings:
                    self._vector_store = Chroma(
                        embedding_function=self.embeddings,
                        persist_directory="./chroma_db"
                    )
            except Exception as e:
                print(f"⚠️ Vector store error: {e}")
                self._vector_store = None
        return self._vector_store

    @vector_store.setter
    def vector_store(self, val):
        self._vector_store = val

    
    def route_question(self, state: State):
        """Determine if question requires RAG or general chat"""
        if not state["messages"]:
            return {"requires_rag": False}
        
        last_message = state["messages"][-1].content.lower()
        
        # Check if we have documents
        doc_count = 0
        if self.vector_store and hasattr(self.vector_store, '_collection'):
            try:
                doc_count = self.vector_store._collection.count()
            except:
                pass
        
        if doc_count > 0:
            rag_keywords = ["pdf", "upload", "document", "file", "according to", "based on", 
                          "from the", "in the file", "tell me about", "what is", "explain", 
                          "summarize", "extract", "point", "resume", "content", "inside"]
            if any(keyword in last_message for keyword in rag_keywords):
                return {"requires_rag": True}
        
        return {"requires_rag": False}
    
    def general_chat(self, state: State):
        """Handle general conversation"""
        if not self.llm:
            return {"messages": [{"role": "assistant", "content": "LLM not available"}], "retrieved_docs": []}
        
        response = self.llm.invoke(state["messages"])
        return {"messages": [response], "retrieved_docs": []}
    
    def rag_retrieval(self, state: State):
        """Retrieve relevant documents and generate response"""
        query = state["messages"][-1].content
        
        if not self.vector_store or not self.llm:
            return self.general_chat(state)
        
        try:
            # Search for relevant documents
            retrieved_docs = self.vector_store.similarity_search(query, k=4)
            
            if not retrieved_docs:
                return self.general_chat(state)
            
            # Create context
            context = "\n\n---\n\n".join([doc.page_content[:800] for doc in retrieved_docs])
            
            prompt = f"""Based on the document content below, answer the question.

DOCUMENT CONTENT:
{context}

QUESTION: {query}

ANSWER:"""
            
            messages = [{"role": "user", "content": prompt}]
            response = self.llm.invoke(messages)
            
            return {
                "messages": [response],
                "retrieved_docs": retrieved_docs
            }
        except Exception as e:
            print(f"RAG error: {e}")
            return self.general_chat(state)
    
    def update_memory(self, state: State):
        """Update conversation memory in database"""
        if state.get("user_id") and len(state["messages"]) >= 2:
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO chats (chat_id, user_id, session_id, message_type, content, domain)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (str(uuid.uuid4()), state["user_id"], state["session_id"], "user",
                      state["messages"][-2].content, state.get("domain", "general")))

                cursor.execute('''
                    INSERT INTO chats (chat_id, user_id, session_id, message_type, content, domain)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (str(uuid.uuid4()), state["user_id"], state["session_id"], "assistant",
                      state["messages"][-1].content, state.get("domain", "general")))

                conn.commit()
            except Error as e:
                print(f"Database error: {e}")
            finally:
                conn.close()

        return {}
    
    def process_uploaded_file(self, file_content, file_name, user_id=None):
        """Process uploaded file and add to vector store"""
        if not self.vector_store:
            return False, "Vector store not available"
        
        try:
            # Create temp file
            suffix = os.path.splitext(file_name)[1]
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode='wb') as tmp_file:
                tmp_file.write(file_content)
                tmp_file_path = tmp_file.name
            
            # Load document
            documents = []
            if file_name.lower().endswith('.pdf'):
                from langchain_community.document_loaders import PyPDFLoader
                loader = PyPDFLoader(tmp_file_path)
                documents = loader.load()
                
            elif file_name.lower().endswith('.txt'):
                try:
                    text_content = file_content.decode('utf-8')
                except:
                    text_content = file_content.decode('latin-1', errors='ignore')
                
                from langchain_core.documents import Document
                doc = Document(
                    page_content=text_content,
                    metadata={"source": file_name, "type": "text"}
                )
                documents = [doc]
            else:
                return False, "Unsupported file type"
            
            if not documents:
                return False, "No content extracted"
            
            # Split into chunks
            chunks = self.text_splitter.split_documents(documents)
            
            # Add to vector store
            if chunks:
                self.vector_store.add_documents(chunks)

                # Store in database
                if user_id:
                    conn = get_db_connection()
                    try:
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT INTO documents (doc_id, user_id, file_name, file_type, file_size)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (str(uuid.uuid4()), user_id, file_name, suffix[1:], len(file_content)))
                        conn.commit()
                    finally:
                        conn.close()

            # Cleanup
            os.unlink(tmp_file_path)

            return True, f"Successfully processed {file_name}"
            
        except Exception as e:
            return False, f"Error: {str(e)}"

# MAIN APPLICATION

# Cached Chatbot System & Workflow Builders
@st.cache_resource
def get_chatbot_system():
    return ChatbotSystem()

@st.cache_resource
def create_workflow(_system):
    graph = StateGraph(State)
    graph.add_node("route_question", _system.route_question)
    graph.add_node("general_chat", _system.general_chat)
    graph.add_node("rag_retrieval", _system.rag_retrieval)
    graph.add_node("update_memory", _system.update_memory)
    graph.add_edge(START, "route_question")
    graph.add_conditional_edges(
        "route_question",
        lambda state: "rag_retrieval" if state.get("requires_rag", False) else "general_chat"
    )
    graph.add_edge("general_chat", "update_memory")
    graph.add_edge("rag_retrieval", "update_memory")
    graph.add_edge("update_memory", END)
    return graph.compile()

# Streamlit config — already set at top of file

# Custom CSS - Premium UI with Floating Mic
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    * {
        font-family: 'Inter', sans-serif;
    }
    
    /* Animated Background */
    .stApp {
        background: radial-gradient(circle at 20% 20%, rgba(14,165,233,0.08), transparent),
                    radial-gradient(circle at 80% 80%, rgba(99,102,241,0.08), transparent),
                    linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    }
    
    /* Glass Sidebar */
    [data-testid="stSidebar"] {
        background: rgba(15, 23, 42, 0.95);
        backdrop-filter: blur(20px);
        border-right: 1px solid rgba(255,255,255,0.1);
    }
    
    /* Chat Messages */
    .user-message {
        display: flex;
        gap: 12px;
        margin: 16px 0;
        justify-content: flex-end;
        animation: slideInRight 0.3s ease;
    }
    
    .user-avatar {
        width: 36px;
        height: 36px;
        background: linear-gradient(135deg, #667eea, #764ba2);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        order: 2;
    }
    
    .message-content {
        background: linear-gradient(135deg, #667eea, #764ba2);
        padding: 12px 18px;
        border-radius: 20px 20px 4px 20px;
        max-width: 70%;
        color: white;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    
    .bot-message {
        display: flex;
        gap: 12px;
        margin: 16px 0;
        justify-content: flex-start;
        animation: slideInLeft 0.3s ease;
    }
    
    .bot-avatar {
        width: 36px;
        height: 36px;
        background: rgba(255,255,255,0.1);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        backdrop-filter: blur(10px);
    }
    
    .bot-message .message-content {
        background: rgba(255,255,255,0.08);
        backdrop-filter: blur(10px);
        border-radius: 20px 20px 20px 4px;
        border: 1px solid rgba(255,255,255,0.1);
    }
    
    /* Animations */
    @keyframes slideInRight {
        from {
            opacity: 0;
            transform: translateX(20px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    @keyframes slideInLeft {
        from {
            opacity: 0;
            transform: translateX(-20px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    .fade-in {
        animation: fadeInUp 0.4s ease;
    }
    
    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(15px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    /* Floating Mic Button */
    .floating-mic {
        position: fixed;
        bottom: 30px;
        right: 30px;
        z-index: 9999;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    
    .mic-button {
        width: 60px;
        height: 60px;
        background: linear-gradient(135deg, #ff4b6e, #ff7a18);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 4px 20px rgba(255,75,110,0.4);
        transition: all 0.3s ease;
        cursor: pointer;
        font-size: 28px;
    }
    
    .mic-button:hover {
        transform: scale(1.1);
        box-shadow: 0 6px 30px rgba(255,75,110,0.6);
    }
    
    .mic-button.recording {
        animation: pulse 1.5s infinite;
        background: linear-gradient(135deg, #ff1a4f, #ff5e00);
    }
    
    @keyframes pulse {
        0%, 100% {
            transform: scale(1);
            box-shadow: 0 0 0 0 rgba(255,75,110,0.7);
        }
        50% {
            transform: scale(1.05);
            box-shadow: 0 0 0 15px rgba(255,75,110,0);
        }
    }
    
    /* Glass Card */
    .glass-card {
        background: rgba(255,255,255,0.03);
        backdrop-filter: blur(10px);
        border-radius: 16px;
        border: 1px solid rgba(255,255,255,0.1);
        padding: 16px;
        transition: all 0.3s ease;
        margin-bottom: 16px;
    }
    
    .glass-card:hover {
        background: rgba(255,255,255,0.05);
    }
    
    /* Control Panel Sections */
    .control-section {
        margin-bottom: 24px;
    }
    
    .control-title {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #94a3b8;
        margin-bottom: 12px;
        font-weight: 600;
    }
    
    /* Status Card */
    .status-card {
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.2);
        border-radius: 12px;
        padding: 12px;
    }
    
    .status-indicator {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #10b981;
        margin-right: 8px;
        animation: pulse 2s infinite;
    }
    
    /* File Card */
    .file-card {
        background: rgba(255,255,255,0.05);
        border-radius: 12px;
        padding: 10px;
        margin: 8px 0;
        border: 1px solid rgba(255,255,255,0.1);
        transition: all 0.3s ease;
    }
    
    .file-card:hover {
        background: rgba(255,255,255,0.08);
        transform: translateX(5px);
    }
    
    /* Domain Badge */
    .domain-badge {
        background: linear-gradient(135deg, #667eea, #764ba2);
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
        display: inline-block;
    }
    
    /* User Profile */
    .user-profile {
        text-align: center;
        padding: 20px 0;
        border-bottom: 1px solid rgba(255,255,255,0.1);
        margin-bottom: 20px;
    }
    
    .user-avatar-large {
        width: 60px;
        height: 60px;
        background: linear-gradient(135deg, #667eea, #764ba2);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 12px auto;
        font-size: 28px;
    }
    
    /* Welcome Screen */
    .welcome-screen {
        text-align: center;
        padding: 60px 20px;
    }
    
    .welcome-title {
        font-size: 3rem;
        background: linear-gradient(135deg, #667eea, #764ba2);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 1rem;
        font-weight: 700;
    }
    
    .welcome-subtitle {
        color: #94a3b8;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
    
    /* Buttons */
    .stButton button {
        background: linear-gradient(135deg, #667eea, #764ba2);
        color: white;
        border: none;
        border-radius: 12px;
        padding: 10px 20px;
        font-weight: 600;
        transition: all 0.3s ease;
        width: 100%;
    }
    
    .stButton button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 20px rgba(102,126,234,0.4);
    }
    
    /* Input Field */
    .stTextInput > div > div > input {
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 12px;
        padding: 12px 16px;
        color: white;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #667eea;
        box-shadow: 0 0 0 2px rgba(102,126,234,0.2);
    }
    
    /* Select Box */
    .stSelectbox > div > div {
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 12px;
    }
    
    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: rgba(255,255,255,0.05);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: rgba(255,255,255,0.2);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(255,255,255,0.3);
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
def initialize_session_state():
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "domain" not in st.session_state:
        st.session_state.domain = "general"
    if "last_input" not in st.session_state:
        st.session_state.last_input = ""
    if "uploaded_files" not in st.session_state:
        st.session_state.uploaded_files = []
    if "voice_text" not in st.session_state:
        st.session_state.voice_text = ""
    if "auto_send" not in st.session_state:
        st.session_state.auto_send = False
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "show_history" not in st.session_state:
        st.session_state.show_history = False
    if "mic_triggered" not in st.session_state:
        st.session_state.mic_triggered = False
    if "current_image" not in st.session_state:
        st.session_state.current_image = None
    if "image_description" not in st.session_state:
        st.session_state.image_description = None

print("🚀 [Step 5] Initializing session state...", flush=True)
initialize_session_state()
print(f"🚀 [Step 6] Session initialized. Authenticated: {st.session_state.authenticated}", flush=True)

# Check authentication
if not st.session_state.authenticated:
    print("🚀 [Step 7] Calling login_ui()...", flush=True)
    login_ui()
    print("🚀 [Step 8] login_ui() rendered, calling st.stop()", flush=True)
    st.stop()
print("🚀 [Step 9] User is authenticated! Initializing chatbot...", flush=True)

# Initialize the chatbot system & workflow (runs ONLY after user logs in!)
chatbot_system = get_chatbot_system()
enhanced_chatbot = create_workflow(chatbot_system)

# Initialize image processor
if 'image_processor' not in st.session_state:
    st.session_state.image_processor = ImageProcessor()
image_processor = st.session_state.image_processor

# Main layout with sidebar for Control Panel
with st.sidebar:
    # User Profile Section
    st.markdown(f"""
    <div class="user-profile">
        <div class="user-avatar-large">
            👤
        </div>
        <div style="font-weight: 600; margin-bottom: 4px;">
            {st.session_state.user.get('full_name', st.session_state.user['username'])}
        </div>
        <div style="font-size: 0.8rem; color: #94a3b8;">
            {st.session_state.user.get('email', 'user@example.com')}
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # ⚙️ Control Panel
    st.markdown("## ⚙️ Control Panel")
    
    # 🎯 Mode Section
    st.markdown('<div class="control-section">', unsafe_allow_html=True)
    st.markdown('<div class="control-title">🎯 Mode</div>', unsafe_allow_html=True)
    selected_domain = st.selectbox(
        "Domain",
        options=list(chatbot_system.domains.keys()),
        format_func=lambda x: f"{x.title()} - {chatbot_system.domains[x]}",
        label_visibility="collapsed",
        key="domain_selector"
    )
    
    if selected_domain != st.session_state.domain:
        st.session_state.domain = selected_domain
        st.session_state.messages.append(("system", f"Domain changed to {selected_domain}"))
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown("---")
    
    # 📊 System Status
    st.markdown('<div class="control-section">', unsafe_allow_html=True)
    st.markdown('<div class="control-title">📊 System Status</div>', unsafe_allow_html=True)
    
    doc_count = 0
    if chatbot_system.vector_store and hasattr(chatbot_system.vector_store, '_collection'):
        try:
            doc_count = chatbot_system.vector_store._collection.count()
        except:
            pass
    
    if doc_count > 0:
        st.markdown(f"""
        <div class="status-card">
            <div>
                <span class="status-indicator"></span>
                <strong style="color: #10b981;">● Ready</strong>
            </div>
            <div style="font-size: 1.5rem; font-weight: 700; margin-top: 8px;">
                {doc_count} chunks loaded
            </div>
            <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">
                Knowledge base active
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.warning("⚠️ No documents loaded")
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown("---")
    
    # 🎤 Voice Input
    st.markdown('<div class="control-section">', unsafe_allow_html=True)
    st.markdown('<div class="control-title">🎤 Voice Input</div>', unsafe_allow_html=True)
    
    # Hidden mic recorder - will be triggered by floating button
    audio_data = mic_recorder(
        start_prompt="Click to speak",
        stop_prompt="Stop recording",
        just_once=True,
        key="voice_recorder_main",
        format="wav"
    )
    
    if audio_data and 'bytes' in audio_data:
        with st.spinner("🎤 Transcribing..."):
            try:
                audio_bytes = io.BytesIO(audio_data['bytes'])
                audio_bytes.seek(0)
                
                recognizer = sr.Recognizer()
                with sr.AudioFile(audio_bytes) as source:
                    recognizer.adjust_for_ambient_noise(source, duration=0.5)
                    audio = recognizer.record(source)
                    text = recognizer.recognize_google(audio)
                    
                    if text:
                        st.session_state.voice_text = text
                        st.success(f"✅ Heard: {text}")
                        time.sleep(0.5)
                        st.session_state.auto_send = True
                        st.rerun()
            except sr.UnknownValueError:
                st.error("❌ Could not understand audio")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
    
    st.info("💡 Click the floating mic button (bottom-right) to speak anytime")
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown("---")
    
    # 📁 Knowledge Base
    st.markdown('<div class="control-section">', unsafe_allow_html=True)
    st.markdown('<div class="control-title">📁 Knowledge Base</div>', unsafe_allow_html=True)
    
    uploaded_files = st.file_uploader(
        "Upload PDF or TXT",
        type=['pdf', 'txt'],
        accept_multiple_files=True,
        key="file_uploader",
        help="Upload documents to enhance AI responses"
    )
    
    if uploaded_files:
        for file in uploaded_files:
            if file.name not in st.session_state.uploaded_files:
                with st.spinner(f"Processing {file.name}..."):
                    success, message = chatbot_system.process_uploaded_file(
                        file.getvalue(), file.name, st.session_state.user_id
                    )
                    if success:
                        st.session_state.uploaded_files.append(file.name)
                        st.success(f"✅ {message}")
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
    
    if st.session_state.uploaded_files:
        st.markdown("#### Uploaded Files:")
        for f in st.session_state.uploaded_files:
            st.markdown(f"""
            <div class="file-card">
                📄 {f}<br>
                <small style="color: #10b981;">✓ Processed & Ready</small>
            </div>
            """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown("---")
    
    # 🖼️ Image Analysis with Cross-Question Support
    st.markdown('<div class="control-section">', unsafe_allow_html=True)
    st.markdown('<div class="control-title">🖼️ Image Analysis</div>', unsafe_allow_html=True)
    
    uploaded_image = st.file_uploader(
        "Upload Image",
        type=['jpg', 'jpeg', 'png', 'webp', 'bmp'],
        key="image_uploader",
        help="Upload an image and AI will describe what's in it"
    )
    
    if uploaded_image:
        # Display thumbnail
        col1, col2 = st.columns([1, 2])
        with col1:
            st.image(uploaded_image, width=80)
        with col2:
            st.caption(f"📷 {uploaded_image.name}")
        
        # Store image in session state for cross-questions
        if st.session_state.current_image != uploaded_image:
            st.session_state.current_image = uploaded_image
            st.session_state.image_description = None
        
        # Describe button
        if st.button("🔍 Describe Image", use_container_width=True, key="describe_img_btn"):
            with st.spinner("🖼️ Analyzing image..."):
                description = st.session_state.image_processor.describe_image(uploaded_image)
                st.session_state.image_description = description
                st.session_state.messages.append(("user", f"📷 Can you describe this image?"))
                st.session_state.messages.append(("assistant", description))
                st.rerun()
        
        # Quick question buttons
        st.markdown("**Quick questions:**")
        col_q1, col_q2, col_q3 = st.columns(3)
        with col_q1:
            if st.button("🏞️ What's in it?", key="img_q1", use_container_width=True):
                if st.session_state.image_description:
                    st.session_state.messages.append(("user", "📷 What's in this image?"))
                    st.session_state.messages.append(("assistant", st.session_state.image_description))
                else:
                    with st.spinner("Analyzing..."):
                        desc = st.session_state.image_processor.describe_image(st.session_state.current_image)
                        st.session_state.image_description = desc
                        st.session_state.messages.append(("user", "📷 What's in this image?"))
                        st.session_state.messages.append(("assistant", desc))
                st.rerun()
        
        with col_q2:
            if st.button("🎨 Main colors?", key="img_q2", use_container_width=True):
                with st.spinner("Analyzing colors..."):
                    desc = st.session_state.image_processor.describe_image(st.session_state.current_image, max_length=25)
                    st.session_state.messages.append(("user", "📷 What are the main colors in this image?"))
                    st.session_state.messages.append(("assistant", f"🎨 {desc}"))
                st.rerun()
        
        with col_q3:
            if st.button("👤 People?", key="img_q3", use_container_width=True):
                with st.spinner("Analyzing..."):
                    desc = st.session_state.image_processor.describe_image(st.session_state.current_image, max_length=30)
                    st.session_state.messages.append(("user", "📷 Are there people in this image?"))
                    st.session_state.messages.append(("assistant", f"👥 {desc}"))
                st.rerun()
        
        # Custom question input for cross-questions
        st.markdown("**Ask anything about this image:**")
        custom_question = st.text_input("", placeholder="e.g., What color is her shirt? Is she smiling?", key="img_custom_question")
        
        if custom_question and st.button("Ask", key="ask_custom", use_container_width=True):
            with st.spinner("Analyzing image..."):
                response = st.session_state.image_processor.ask_question_about_image(
                    st.session_state.current_image, custom_question
                )
                st.session_state.messages.append(("user", f"📷 {custom_question}"))
                st.session_state.messages.append(("assistant", response))
                st.rerun()
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown("---")
    
    # 📜 History
    st.markdown('<div class="control-section">', unsafe_allow_html=True)
    st.markdown('<div class="control-title">📜 History</div>', unsafe_allow_html=True)
    
    if st.button("Show Recent Chats", use_container_width=True, key="show_history_btn"):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT message_type, content, timestamp
                FROM chats WHERE user_id = ?
                ORDER BY timestamp DESC LIMIT 10
            """, (st.session_state.user_id,))
            history = cursor.fetchall()
        finally:
            conn.close()
        if history:
            for msg_type, content, timestamp in history:
                icon = "👤" if msg_type == "user" else "✨"
                st.markdown(f"""
                <div style="font-size: 0.8rem; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <div>{icon} <strong>{msg_type.title()}</strong> <span style="color:#64748b; font-size:0.7rem;">{timestamp[:16]}</span></div>
                    <div style="color:#94a3b8;">{content[:60]}...</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No chat history yet")
    
    st.markdown("</div>", unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Logout button
    if st.button("🚪 Logout", use_container_width=True, key="logout_btn"):
        if 'session_id' in st.session_state:
            AuthManager.end_session(st.session_state.session_id)
        for key in ['authenticated', 'user', 'session_id', 'user_id', 'messages']:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

# Main chat area
st.markdown("""
<div style="text-align: center; padding: 20px 0 10px 0;">
    <h1 style="font-size: 2.5rem; background: linear-gradient(135deg, #667eea, #764ba2); 
               -webkit-background-clip: text; -webkit-text-fill-color: transparent; 
               margin-bottom: 0.5rem;">
        ✨ AI Operating System
    </h1>
    <p style="color: #94a3b8;">Your intelligent assistant for everything</p>
</div>
""", unsafe_allow_html=True)

# Chat container
chat_container = st.container()

with chat_container:
    if not st.session_state.messages:
        # Welcome screen
        st.markdown("""
        <div class="welcome-screen">
            <div class="welcome-title">Welcome to AI OS</div>
            <div class="welcome-subtitle">Ask me anything, upload documents, or use voice commands</div>
            <div style="display: flex; gap: 10px; justify-content: center; margin-top: 30px; flex-wrap: wrap;">
                <span class="domain-badge">💬 General Chat</span>
                <span class="domain-badge">📁 Document Q&A</span>
                <span class="domain-badge">🎤 Voice Commands</span>
                <span class="domain-badge">🖼️ Image Analysis</span>
                <span class="domain-badge">🔍 Smart Search</span>
            </div>
            <div style="margin-top: 40px;">
                <p style="color: #64748b;">💡 Tip: Click the floating mic button (bottom-right) to speak anytime!</p>
                <p style="color: #64748b;">🖼️ Tip: Upload an image and ask multiple questions about it!</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Display chat messages
        for role, msg in st.session_state.messages:
            if role == "user":
                st.markdown(f"""
                <div class="user-message">
                    <div class="user-avatar">👤</div>
                    <div class="message-content">{msg}</div>
                </div>
                """, unsafe_allow_html=True)
            elif role == "assistant":
                st.markdown(f"""
                <div class="bot-message">
                    <div class="bot-avatar">✨</div>
                    <div class="message-content">{msg}</div>
                </div>
                """, unsafe_allow_html=True)
            elif role == "system":
                st.info(f"ℹ️ {msg}")

# Input area
st.markdown("---")
col1, col2 = st.columns([5, 1])
with col1:
    user_input = st.text_input(
        "Message",
        value=st.session_state.voice_text,
        placeholder=f"Ask about {st.session_state.domain}...",
        label_visibility="collapsed",
        key="user_input_field"
    )
with col2:
    send_button = st.button("Send →", use_container_width=True)

# Process auto-send from voice
if st.session_state.auto_send and st.session_state.voice_text:
    message_to_send = st.session_state.voice_text
    st.session_state.auto_send = False
    st.session_state.voice_text = ""
    
    if message_to_send.strip():
        st.session_state.messages.append(("user", f"🎤 {message_to_send}"))
        
        state = {
            "messages": [{"role": "user", "content": message_to_send}],
            "domain": st.session_state.domain,
            "session_id": st.session_state.session_id,
            "user_id": st.session_state.user_id,
            "retrieved_docs": [],
            "requires_rag": False
        }
        
        with st.spinner("🤔 Thinking..."):
            try:
                response = enhanced_chatbot.invoke(state)
                reply = response["messages"][-1].content
                st.session_state.messages.append(("assistant", reply))
                
                if response.get("retrieved_docs"):
                    with st.expander("📚 Sources"):
                        for i, doc in enumerate(response["retrieved_docs"][:3]):
                            st.write(f"**Source {i+1}:** {doc.page_content[:200]}...")
            except Exception as e:
                st.session_state.messages.append(("assistant", f"Error: {str(e)}"))
        
        st.rerun()

# Regular send
elif send_button and user_input.strip():
    message_to_send = user_input
    
    st.session_state.messages.append(("user", message_to_send))
    
    state = {
        "messages": [{"role": "user", "content": message_to_send}],
        "domain": st.session_state.domain,
        "session_id": st.session_state.session_id,
        "user_id": st.session_state.user_id,
        "retrieved_docs": [],
        "requires_rag": False
    }
    
    with st.spinner("🤔 Thinking..."):
        try:
            response = enhanced_chatbot.invoke(state)
            reply = response["messages"][-1].content
            st.session_state.messages.append(("assistant", reply))
            
            if response.get("retrieved_docs"):
                with st.expander("📚 Sources"):
                    for i, doc in enumerate(response["retrieved_docs"][:3]):
                        st.write(f"**Source {i+1}:** {doc.page_content[:200]}...")
        except Exception as e:
            st.session_state.messages.append(("assistant", f"Error: {str(e)}"))
    
    st.rerun()

# Footer
st.markdown("""
<div style="text-align: center; padding: 20px; color: #64748b; font-size: 0.8rem;">
    ✨ AI Operating System | Voice Enabled | RAG Knowledge Base | Image Analysis | Cross-Questions | LangGraph + Groq
</div>
""", unsafe_allow_html=True)