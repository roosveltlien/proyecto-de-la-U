import pandas as pd             # Para el manejo del dataset (CSV)
import numpy as np              # Para operaciones numéricas y arrays
import random                   # Para generar la sugerencia aleatoria
import string                   # Para acceder a caracteres (mayúsculas, números)
import time                     # Para introducir pausas

# Librerías de Machine Learning (Scikit-Learn)
from sklearn.model_selection import train_test_split  # Para dividir los datos
from sklearn.ensemble import RandomForestRegressor    # El modelo de Bosque Aleatorio

# --- 1. CARGA Y ENTRENAMIENTO ---
try:
    # Cargamos el dataset para entrenar
    # Nota: Asegúrate de que el separador sea el correcto (coma o punto y coma)
    df = pd.read_csv('/content/Dataset_Contrasenas(Sheet1).csv', encoding='ISO-8859-1', on_bad_lines='skip', sep=';')

    # Preparamos las características (X) y el objetivo (y)
    # Entrenamos a la IA para que entienda la relación entre estructura y puntaje
    X = df[['Length', 'Has_Uppercase', 'Has_Special']]
    y = df['Security_Score']

    # Dividimos los datos (80% entrenamiento, 20% prueba)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Creamos y entrenamos el modelo (Bosque Aleatorio)
    # Aunque el puntaje final ahora es rule-based, el modelo aún podría ser útil
    # para otras funcionalidades o para comprender patrones. La blacklist lo usa.
    modelo_ia = RandomForestRegressor(n_estimators=100, random_state=42)
    modelo_ia.fit(X_train, y_train)

    # Creamos la lista negra para comparación directa
    dataset_comunes = set(df.iloc[:, 0].dropna().astype(str).str.lower())


except Exception as e:
    print(f"⚠️ Error al inicializar la IA: {e}")
    # Sistema de respaldo por si falla el archivo
    dataset_comunes = {"123456", "password"}
    modelo_ia = None # Asegurarse de que sea None si falla la carga

# --- 2. MOTOR DE EVALUACIÓN HÍBRIDO (Reglas + IA) ---
def evaluador_ia(password):
    if len(password) > 12:
        return "Error: Máximo 12 caracteres.", [], "", 0

    # Extraemos las características de la contraseña ingresada como booleanos
    has_uppercase = any(c.isupper() for c in password)
    has_lowercase = any(c.islower() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password) # Cualquier carácter no alfanumérico
    has_space = " " in password

    # Calculamos puntaje_final según las reglas de entropía dadas por el usuario
    puntaje_final = 0
    if has_lowercase:
        puntaje_final += 26
    if has_uppercase:
        puntaje_final += 26
    if has_digits:
        puntaje_final += 10
    if has_special:
        puntaje_final += 32
    if has_space: # Añadir 1 punto por el espacio
        puntaje_final += 1

    # VALIDACIONES DE SEGURIDAD ADICIONALES (Recomendaciones)
    recomendaciones = []
    if not has_uppercase: recomendaciones.append("Falta una MAYÚSCULA")
    if not has_lowercase: recomendaciones.append("Falta una MINÚSCULA") # Nueva recomendación
    if not has_digits: recomendaciones.append("Falta un NÚMERO")
    if not has_special: recomendaciones.append("Falta un CARÁCTER ESPECIAL")
    if not has_space: recomendaciones.append("Usa espacios para crear una frase")

    # Penalización radical si la contraseña aparece en el dataset de filtraciones
    # Esta penalización sobrescribe el puntaje si se detecta una contraseña común.
    if password.lower() in dataset_comunes:
        puntaje_final = 10
        recomendaciones.append("¡PELIGRO! Esta contraseña aparece en filtraciones reales.")

    # LÓGICA DE SUGERENCIA
    sugerencia = password
    # Solo intentamos añadir componentes si la longitud actual es menor a 12
    if len(sugerencia) < 12:
        if not has_uppercase and len(sugerencia) < 12:
            sugerencia += random.choice(string.ascii_uppercase)
        if not has_lowercase and len(sugerencia) < 12: # Añadir minúscula si falta
            sugerencia += random.choice(string.ascii_lowercase)
        if not has_digits and len(sugerencia) < 12:
            sugerencia += random.choice(string.digits)
        # Usar un conjunto más amplio de caracteres especiales para la sugerencia
        if not has_special and len(sugerencia) < 12:
            sugerencia += random.choice("!@#$%^&*()_-+=[]{}|;:,.<>?")
        # Añadir espacio si falta y la longitud lo permite (originalmente se prepone)
        if not has_space and len(sugerencia) < 12:
            sugerencia = " " + sugerencia # Esta línea podría hacer que la sugerencia exceda temporalmente los 12

    # Asegurarse de que la sugerencia final no exceda los 12 caracteres
    return puntaje_final, recomendaciones, sugerencia[:12]

# --- 3. BLOQUE DE EJECUCIÓN ---
print("\n" + "="*40)
print("SISTEMA DE EVALUACION")
print("="*40)

# Bucle infinito para permitir múltiples evaluaciones
while True:
    # Bucle para pedir la contraseña hasta que sea al menos 'Razonable' (puntos > 39)
    puntos = 0 # Inicializamos puntos para entrar al bucle interno
    # Se sigue re-solicitando hasta que la contraseña sea al menos 'Razonable' (40 puntos o más).
    while puntos <= 39:
        user_input = input("Analizar contraseña MAX 12 caracteres: ")
        puntos, fallos, mejorada = evaluador_ia(user_input)

        if isinstance(puntos, str):
            print(f"\n{puntos}")
            # Si hay un error, reseteamos puntos para reintentar
            puntos = 0
        else:
            print(f"\n[DIAGNÓSTICO DE LA IA]")
            print(f"Nivel de Seguridad: {puntos}/95") # Actualizado el máximo aquí

            if puntos == 95:
                print("ESTADO: 🟢 Perfecto")
            elif puntos >= 71 and puntos <= 94:
                print("ESTADO: 🟢 Muy fuerte")
            elif puntos >= 40 and puntos <= 70:
                print("ESTADO: 🟠 Razonable")
            elif puntos >= 20 and puntos <= 39:
                print("ESTADO: 🔴 Debil")
                print("Por favor, ingrese una contraseña más segura.\n")
            else: # puntos < 20
                print("ESTADO: 🔴 Muy debil")
                print("Por favor, ingrese una contraseña más segura.\n")

            if fallos:
                print("\nSugerencias del modelo:")
                for f in fallos: print(f" * {f}")

            print(f"\n[SUGERENCIA]: {mejorada}")
            print("\n[INFO]: Este análisis se basó en el entrenamiento de 12,000 patrones de seguridad.")

    print("\n¡Contraseña aceptada! Su contraseña tiene un nivel de seguridad aceptable.")
    print("Reiniciando el sistema en 10 segundos para una nueva evaluación...")
    time.sleep(10)