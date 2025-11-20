# 👚 DrobeMate – Your Smart Wardrobe Companion

**DrobeMate** is a modern wardrobe management system built with **Django** and **PostgreSQL**.  
It helps users organize their clothing, plan daily outfits, and get smart suggestions based on weather and personal style.

---

## 🌟 Features

### 🧥 Wardrobe Management
- Upload and manage clothing items  
- Categorize items (tops, bottoms, footwear, accessories)  
- Store colors, seasons, brands, and more  

### 🗓️ Outfit Planning
- Create outfits by combining clothing items  
- Save outfits for specific dates or events  
- Track wear history (Coming Soon)  

### 🌤️ Smart Suggestions
- Weather-based outfit recommendations *(Coming Soon)*  
- Personalized AI-powered outfit suggestions *(Future Enhancement)*  

### 🛍️ Shopping Integration
- Identify missing wardrobe items  
- Wishlist integration *(Future)*  

---

## ⚙️ Tech Stack

| Tech        | Description                    |
|------------|--------------------------------|
| Python 3.9+ | Backend Language               |
| Django      | Web Framework                   |
| PostgreSQL  | Database                        |
| Next.js    | Frontend (handled by teammate)  |
| HTML/CSS    | Basic template testing (optional) |

---

## 🚀 Getting Started

### 🔧 Prerequisites
- Python 3.9 or higher  
- PostgreSQL (optional for initial setup)  
- pip package manager  

### 📁 Project Setup

```bash
# 1. Clone the repository
git clone https://github.com/Gokul-Peace/DrobeMate.git
cd drobemate

# 2. Create virtual environment
python3 -m venv drobemateenv

# 3. Activate the environment
source drobemateenv/bin/activate   # Mac/Linux
drobemateenv\Scripts\activate      # Windows

# 4. Install dependencies
pip install django

# 5. Run migrations (after adding models)
python3 manage.py migrate

# 6. Start development server
python3 manage.py runserver
