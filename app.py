import streamlit as st
import calendar
import io
import os
import pandas as pd
import bcrypt

from datetime import date, timedelta
from supabase import create_client, Client


SUPABASE_URL = st.secrets.get("SUPABASE_URL")
SUPABASE_KEY = st.secrets.get("SUPABASE_ANON_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    st.error("❌ Supabase non configuré (secrets manquants)")
    st.stop()

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

TRANSPORTS = ["Voiture", "Vélo", "Transport"]
TAUX = {
    "Voiture": 0.10,
    "Vélo": 0.00,
    "Transport": 0.00
}

PLAFOND_MENSUEL = 60.0

JOURS_FR = [
    "Lundi", "Mardi", "Mercredi",
    "Jeudi", "Vendredi", "Samedi", "Dimanche"
]

MOIS_FR = [
    "Janvier", "Février", "Mars", "Avril", "Mai", "Juin",
    "Juillet", "Août", "Septembre", "Octobre", "Novembre", "Décembre"
]
def sb_select(table, filters=None):
    q = supabase.table(table).select("*")
    if filters:
        for k, v in filters.items():
            q = q.eq(k, v)
    return q.execute().data or []


def sb_insert(table, data):
    return supabase.table(table).insert(data).execute()


def sb_update(table, data, filters):
    q = supabase.table(table).update(data)
    for k, v in filters.items():
        q = q.eq(k, v)
    return q.execute()


def sb_delete(table, filters):
    q = supabase.table(table).delete()
    for k, v in filters.items():
        q = q.eq(k, v)
    return q.execute()
def get_periode_reference(annee: int, mois: int):
    """
    Période métier 20 → 20

    - Janvier : 01/01 → 20/01
    - Autres mois : 21/(mois-1) → 20/mois

    Retour :
    - start : date
    - end   : date
    - mois_comptable : str (YYYY-MM)
    """

    if mois == 1:
        start = date(annee, 1, 1)
        end = date(annee, 1, 20)
        mois_comptable = f"{annee}-01"
    else:
        start = date(annee, mois - 1, 21)
        end = date(annee, mois, 20)
        mois_comptable = f"{annee}-{mois:02d}"

    return start, end, mois_comptable

    rows = (
        supabase
        .table("trajets")
        .select("transport")
        .eq("user_id", user_id)
        .gte("jour", periode_start.isoformat())
        .lte("jour", periode_end.isoformat())
        .execute()
        .data
    )
def total_mois_courant(user_id, annee, mois, km):
    """
    Calcul du mois M : du 01/M au 20/M
    """
    start = date(annee, mois, 1)
    end = date(annee, mois, 20)

    rows = (
        supabase
        .table("trajets")
        .select("transport")
        .eq("user_id", user_id)
        .gte("jour", start.isoformat())
        .lte("jour", end.isoformat())
        .execute()
        .data
    )

    if not rows:
        return 0.0, 0.0

    df = pd.DataFrame(rows)
    brut = (df["transport"].map(TAUX) * km).sum()
    plafonne = min(brut, PLAFOND_MENSUEL)

    return round(brut, 2), round(plafonne, 2)



def total_mois_periode(user_id, periode_start, periode_end, km):
    rows = (
        supabase
        .table("trajets")
        .select("transport")
        .eq("user_id", user_id)
        .gte("jour", periode_start.isoformat())
        .lte("jour", periode_end.isoformat())
        .execute()
        .data
    )

    if not rows:
        return 0.0, 0.0

    df = pd.DataFrame(rows)

    # ✅ calcul journalier correct
    df["taux"] = df["transport"].map(TAUX)
    df["km_effectif"] = df["km_utilise"].fillna(km)
    df["indemnite_jour"] = df["taux"] * df["km_effectif"]

    brut = df["indemnite_jour"].sum()
    plafonne = min(brut, PLAFOND_MENSUEL)

    return round(brut, 2), round(plafonne, 2)


def valider_mois(
    user_id,
    annee,
    mois,
    km
):
    """
    Validation d'un mois M avec régularisation AUTOMATIQUE du mois M-1.

    Règles :
    - Mois M calculé sur 01/M → 20/M
    - Plafond mensuel appliqué sur M
    - Le mois M régularise TOUJOURS le mois M-1 si nécessaire
    """

    # =============================
    # Identification du mois courant
    # =============================
    mois_courant = f"{annee}-{mois:02d}"

    # ======================================
    # 1️⃣ Calcul du mois courant (01 → 20)
    # ======================================
    brut, plafonne = total_mois_courant(
        user_id,
        annee,
        mois,
        km
    )

    # ==================================================
    # 2️⃣ Calcul de la régularisation du mois précédent
    # ==================================================
    regul, mois_prec = calcul_regularisation_mois_precedent(
        user_id,
        mois_courant,
        plafonne
    )

    # ==========================================
    # 3️⃣ Enregistrement / mise à jour validation
    # ==========================================
    supabase.table("validations").upsert({
        "user_id": user_id,
        "mois": mois_courant,
        "km_utilise": km,
        "brut": brut,
        "plafonne": plafonne
    }).execute()

    # ==================================
    # 4️⃣ Enregistrement régularisation
    # ==================================
    if regul > 0 and mois_prec:
        supabase.table("regularisations").insert({
            "user_id": user_id,
            "mois_source": mois_prec,
            "mois_cible": mois_courant,
            "montant": regul
        }).execute()

    # ======================
    # 5️⃣ Résumé du paiement
    # ======================
    return {
        "mois": mois_courant,
        "brut": brut,
        "plafonne": plafonne,
        "regularisation": regul,
        # ⬇️ tu peux modifier cette ligne librement
        "total_paye": round(plafonne + regul, 2)
    }

    if not rows:
        return 0.0, 0.0

    df = pd.DataFrame(rows)
    df["taux"] = df["transport"].map(TAUX)

    brut = (df["taux"] * km).sum()
    plafonne = min(brut, PLAFOND_MENSUEL)

    return round(brut, 2), round(plafonne, 2)
def total_deja_paye(user_id, mois):
    """
    Retourne le TOTAL réellement payé pour un mois donné.
    Inclut :
    - le montant plafonné validé
    - toutes les régularisations provenant de ce mois
    """

    total = 0.0

    # ===== validation du mois =====
    res_val = (
        supabase
        .table("validations")
        .select("plafonne")
        .eq("user_id", user_id)
        .eq("mois", mois)
        .execute()
        .data
    )

    if res_val:
        total += float(res_val[0]["plafonne"])

    # ===== régularisations issues de ce mois =====
    res_reg = (
        supabase
        .table("regularisations")
        .select("montant")
        .eq("user_id", user_id)
        .eq("mois_source", mois)
        .execute()
        .data
    )

    if res_reg:
        total += sum(float(r["montant"]) for r in res_reg)

    return round(total, 2)





def calcul_regularisation_mois_precedent(
    user_id,
    mois_courant,
    montant_mois_courant
):
    """
    Le mois courant complète TOUJOURS le mois précédent si nécessaire.
    La régularisation est plafonnée par :
    - le plafond restant du mois précédent
    - le montant plafonné du mois courant
    """

    an, m = map(int, mois_courant.split("-"))

    # Janvier n'a pas de mois précédent
    if m == 1:
        return 0.0, None

    mois_prec = f"{an}-{m-1:02d}"

    # Total réellement payé pour le mois précédent
    deja_paye = total_deja_paye(user_id, mois_prec)

    if deja_paye >= PLAFOND_MENSUEL:
        return 0.0, mois_prec

    manque = PLAFOND_MENSUEL - deja_paye

    regul = min(montant_mois_courant, manque)

    return round(regul, 2), mois_prec


def total_mois_comptable(user_id, mois_comptable, km):
    """
    Calcule le TOTAL réel d'un mois comptable,
    en agrégeant toutes les périodes liées à ce mois.
    """

    annee, mois = map(int, mois_comptable.split("-"))

    if mois == 1:
        start = date(annee, 1, 1)
        end = date(annee, 1, 20)
    else:
        start = date(annee, mois - 1, 21)
        end = date(annee, mois, 20)

    rows = (
        supabase
        .table("trajets")
        .select("transport")
        .eq("user_id", user_id)
        .gte("jour", start.isoformat())
        .lte("jour", end.isoformat())
        .execute()
        .data
    )

    if not rows:
        return 0.0, 0.0

    df = pd.DataFrame(rows)

    # ✅ calcul journalier correct
    df["taux"] = df["transport"].map(TAUX)
    df["km_effectif"] = df["km_utilise"].fillna(km)
    df["indemnite_jour"] = df["taux"] * df["km_effectif"]

    brut = df["indemnite_jour"].sum()
    plafonne = min(brut, PLAFOND_MENSUEL)

    return round(brut, 2), round(plafonne, 2)

    brut = (df["transport"].map(TAUX) * km).sum()
    plafonne = min(brut, PLAFOND_MENSUEL)

    return round(brut, 2), round(plafonne, 2)

def total_mois_comptable(user_id, mois_comptable, km):
    """
    Calcule le TOTAL réel d'un mois comptable,
    en agrégeant toutes les périodes liées à ce mois.
    """

    annee, mois = map(int, mois_comptable.split("-"))

    # Période principale
    if mois == 1:
        start = date(annee, 1, 1)
        end = date(annee, 1, 20)
    else:
        start = date(annee, mois - 1, 21)
        end = date(annee, mois, 20)

    # ⚠️ IMPORTANT : on inclut AUSSI les ajouts ultérieurs
    rows = (
        supabase
        .table("trajets")
        .select("transport")
        .eq("user_id", user_id)
        .gte("jour", start.isoformat())
        .lte("jour", end.isoformat())
        .execute()
        .data
    )

    if not rows:
        return 0.0, 0.0

    df = pd.DataFrame(rows)
    brut = (df["transport"].map(TAUX) * km).sum()
    plafonne = min(brut, PLAFOND_MENSUEL)

    return round(brut, 2), round(plafonne, 2)



def total_regularisations(user_id, mois_cible):
    rows = (
        supabase
        .table("regularisations")
        .select("montant")
        .eq("user_id", user_id)
        .eq("mois_cible", mois_cible)
        .execute()
        .data
    )

    if not rows:
        return 0.0

    return round(sum(r["montant"] for r in rows), 2)

def creer_regularisation_si_necessaire(
    user_id,
    mois_source,
    ancien_brut,
    ancien_plafonne,
    nouveau_brut,
    nouveau_plafonne
):
    if nouveau_plafonne > ancien_plafonne:
        if ancien_plafonne >= PLAFOND_MENSUEL:
            return
        diff = nouveau_plafonne - ancien_plafonne

    elif nouveau_plafonne < ancien_plafonne:
        diff = nouveau_plafonne - ancien_plafonne
    else:
        return

    diff = round(diff, 2)
    if diff == 0:
        return

    an, m = map(int, mois_source.split("-"))
    mois_cible = f"{an+1}-01" if m == 12 else f"{an}-{m+1:02d}"

    supabase.table("regularisations").insert({
        "user_id": user_id,
        "mois_source": mois_source,
        "mois_cible": mois_cible,
        "montant": diff
    }).execute()


def montant_final_paye(user_id, periode_start, periode_end, mois_comptable, km):
    brut, plafonne = total_mois_periode(
        user_id,
        periode_start,
        periode_end,
        km
    )

    regul = total_regularisations(user_id, mois_comptable)

    total = round(plafonne + regul, 2)

    return {
        "brut": round(brut, 2),
        "plafonne": round(plafonne, 2),
        "regularisation": round(regul, 2),
        "total_paye": total,
        "plafond_atteint": brut > PLAFOND_MENSUEL
    }

def login_user(login, pwd):
    try:
        res = (
            supabase
            .table("users")
            .select("*")
            .eq("login", login)
            .execute()
        )

        if not res.data:
            return None

        user = res.data[0]

        if bcrypt.checkpw(
            pwd.encode(),
            user["password"].encode()
        ):
            return user

        return None

    except Exception as e:
        st.error(f"Erreur login Supabase : {e}")
        return None


def init_admin():
    res = (
        supabase
        .table("users")
        .select("id")
        .eq("login", "admin")
        .execute()
    )

    if res.data:
        return  # admin déjà présent

    hpwd = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode()

    supabase.table("users").insert({
        "nom": "Admin",
        "prenom": "Root",
        "login": "admin",
        "password": hpwd,
        "km": 0,
        "is_admin": True,
        "must_change_pwd": True
    }).execute()


# ⚠️ À appeler UNE SEULE FOIS
init_admin()


if "user" not in st.session_state:
    st.session_state.user = None

if "edit_mode" not in st.session_state:
    st.session_state.edit_mode = False

if "jours_selectionnes" not in st.session_state:
    st.session_state.jours_selectionnes = set()


if st.session_state.user is None:
    st.set_page_config("Indemnités kilométriques", layout="wide")
    st.title("Connexion")

    login_input = st.text_input("Login")
    pwd = st.text_input("Mot de passe", type="password")

    if st.button("Connexion"):
        u = login_user(login_input, pwd)
        if u:
            st.session_state.user = u
            st.rerun()
        else:
            st.error("Identifiants incorrects")

    st.stop()


uid = st.session_state.user["id"]
nom = st.session_state.user["nom"]
prenom = st.session_state.user["prenom"]
login = st.session_state.user["login"]
km = st.session_state.user["km"]
is_admin = st.session_state.user["is_admin"]
must_change_pwd = st.session_state.user["must_change_pwd"]

st.set_page_config("Indemnités kilométriques", layout="wide")

st.markdown("""
<style>
.day-box {
    padding: 4px;
    border-radius: 6px;
}
.day-locked {
    opacity: 0.45;
}
.day-new {
    color: #2ecc71;
    font-size: 0.8em;
}
.day-info {
    font-size: 0.75em;
}
</style>
""", unsafe_allow_html=True)


if must_change_pwd:
    st.warning("Vous devez changer votre mot de passe")

    p1 = st.text_input("Nouveau mot de passe", type="password")
    p2 = st.text_input("Confirmation", type="password")

    if st.button("Changer le mot de passe"):
        if not p1 or p1 != p2:
            st.error("Mot de passe invalide")
        else:
            hpwd = bcrypt.hashpw(p1.encode(), bcrypt.gensalt()).decode()

            supabase.table("users").update({
                "password": hpwd,
                "must_change_pwd": False
            }).eq("id", uid).execute()

            st.success("Mot de passe modifié")
            st.session_state.user = None
            st.rerun()

    st.stop()

st.sidebar.write(f"👤 {prenom} {nom}")

if st.sidebar.button("Déconnexion", key="logout_btn"):
    st.session_state.user = None
    st.rerun()

menu = st.sidebar.radio(
    "Menu",
    ["Encodage", "Historique"] if not is_admin else
    ["Utilisateurs", "Encodage", "Validation", "Exports"],
    key="menu_radio"
)

annee = mois_num = None
periode_start = periode_end = None
mois_comptable = None

if menu in ["Encodage", "Validation", "Exports"]:

    today = date.today()

    annee = st.selectbox(
        "Année",
        range(today.year - 1, today.year + 3),
        index=1,
        key="select_annee"
    )

    mois_label = st.selectbox(
        "Mois",
        MOIS_FR,
        index=today.month - 1,
        key="select_mois"
    )

    mois_num = MOIS_FR.index(mois_label) + 1

    periode_start, periode_end, mois_comptable = get_periode_reference(
        annee,
        mois_num
    )

    st.caption(
        f"📅 Période de référence : "
        f"{periode_start.strftime('%d/%m/%Y')} → "
        f"{periode_end.strftime('%d/%m/%Y')}"
    )

def calendrier(user_id, admin=False):

    # ===== récupération trajets période =====
    rows = (
        supabase
        .table("trajets")
        .select("jour, transport, validated, sent_for_validation")
        .eq("user_id", user_id)
        .gte("jour", periode_start.isoformat())
        .lte("jour", periode_end.isoformat())
        .execute()
        .data
    )

    data = {
        date.fromisoformat(r["jour"]): {
            "transport": r["transport"],
            "validated": bool(r["validated"]),
            "sent": bool(r.get("sent_for_validation", False))
        }
        for r in rows
    }

    st.markdown(f"""
**Période affichée**  
📅 {periode_start.strftime('%d/%m/%Y')} → {periode_end.strftime('%d/%m/%Y')}
""")

    jours = []

    # ===== génération des jours de la période =====
    current = periode_start
    days = []

    while current <= periode_end:
        days.append(current)
        current += timedelta(days=1)

    # ===== alignement semaine (lundi → dimanche) =====
    first_weekday = days[0].weekday()
    for _ in range(first_weekday):
        days.insert(0, None)

    # ===== affichage par semaines =====
    for i in range(0, len(days), 7):

        cols = st.columns(7)
        week = days[i:i+7]

        for col, day in zip(cols, week):

            with col:

                if day is None:
                    st.write("")
                    continue

                wd = day.weekday()
                is_weekend = wd >= 5

                existe = day in data
                validated = existe and data[day]["validated"]
                sent = existe and data[day]["sent"]

                locked = (
                    is_weekend
                    or ((sent or validated) and not admin)
                )

                label = f"{JOURS_FR[wd][:2]} {day.strftime('%d/%m')}"

                # ==========================
                # WEEK-END
                # ==========================
                if is_weekend:

                    st.checkbox(label, disabled=True)
                    st.caption("⛔ Week-end")

                    val = False

                # ==========================
                # JOUR EXISTANT
                # ==========================
                elif existe:

                    icon = {
                        "Voiture": "🚗",
                        "Vélo": "🚲",
                        "Transport": "🚌"
                    }.get(data[day]["transport"], "❓")

                    status = "✅" if validated else "⏳" if sent else ""

                    # ===== MODE ÉDITION =====
                    if st.session_state.edit_mode:

                        selected = day.day in st.session_state.jours_selectionnes

                        toggle = st.checkbox(
                            label,
                            value=selected,
                            disabled=locked
                        )

                        if toggle:
                            st.session_state.jours_selectionnes.add(day.day)
                        else:
                            st.session_state.jours_selectionnes.discard(day.day)

                        st.caption(f"{icon} {data[day]['transport']} {status}")

                        val = True

                    # ===== MODE NORMAL =====
                    else:

                        st.checkbox(label, value=True, disabled=True)
                        st.caption(f"{icon} {data[day]['transport']} {status}")

                        val = True

                # ==========================
                # NOUVEAU JOUR
                # ==========================
                else:

                    val = st.checkbox(label, disabled=is_weekend)

                    if val:
                        st.caption("➕ Nouveau")

                if not is_weekend:
                    jours.append((day, val, existe, validated, sent))

    return jours

save_clicked = False
send_clicked = False

if menu == "Encodage":

    st.header(
        f"Encodage des trajets — "
        f"{periode_start.strftime('%d/%m/%Y')} → {periode_end.strftime('%d/%m/%Y')}"
    )
    st.divider()

    # ==================================================
    # UTILISATEUR CIBLE
    # ==================================================
    if is_admin:

        res_users = (
            supabase
            .table("users")
            .select("id, prenom, nom")
            .neq("login", "admin")
            .order("nom")
            .execute()
        )

        users = res_users.data or []

        if not users:
            st.warning("Aucun utilisateur disponible.")
            st.stop()

        labels = []
        user_map = {}

        for u in users:
            label = f"{u['prenom']} {u['nom']}"
            labels.append(label)
            user_map[label] = u["id"]

        selected_label = st.selectbox(
            "Utilisateur à encoder",
            labels
        )

        cible = user_map[selected_label]

    else:

        cible = uid

    # ==================================================
    # TRANSPORT PAR DÉFAUT
    # ==================================================
    transport_global = st.selectbox(
        "Moyen de transport pour les nouveaux jours",
        TRANSPORTS
    )

    changer_transport = st.checkbox(
        "Changer le transport des jours existants sélectionnés",
        value=False
    )

    st.divider()

    # ==================================================
    # MODE ÉDITION
    # ==================================================
    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("✏️ Modifier l’encodage"):
            st.session_state.edit_mode = True

    with col2:
        save_clicked = st.button("💾 Enregistrer")

    with col3:
        delete_selected = st.button("🗑 Supprimer sélection")

    if st.session_state.edit_mode:
        st.info(
            "Mode modification actif : sélectionnez les jours existants "
            "puis cliquez sur Enregistrer ou Supprimer."
        )

    # ==================================================
    # CALENDRIER
    # ==================================================
    jours = calendrier(cible, admin=is_admin)

    # ==================================================
    # SUPPRESSION
    # ==================================================
    if delete_selected and st.session_state.edit_mode:

        jours_supprimes = 0

        for day in list(st.session_state.jours_selectionnes):

            jour_date = date(annee, mois_num, day)

            if not (periode_start <= jour_date <= periode_end):
                continue

            supabase.table("trajets") \
                .delete() \
                .eq("user_id", cible) \
                .eq("jour", jour_date.isoformat()) \
                .execute()

            jours_supprimes += 1

        st.session_state.jours_selectionnes.clear()

        st.success(f"{jours_supprimes} jour(s) supprimé(s).")
        st.rerun()

    # ==================================================
    # ENREGISTREMENT
    # ==================================================
    if save_clicked:

        for day, val, existe, validated, sent in jours:

            jour_iso = day.isoformat()

            if not (periode_start <= day <= periode_end):
                continue

            # AJOUT
            if val and not existe:

                supabase.table("trajets").insert({
                    "user_id": cible,
                    "jour": jour_iso,
                    "transport": transport_global,
                    "km_utilise": km,
                    "validated": False,
                    "sent_for_validation": False
                }).execute()

            # SUPPRESSION
            elif existe and st.session_state.edit_mode and not val:

                supabase.table("trajets") \
                    .delete() \
                    .eq("user_id", cible) \
                    .eq("jour", jour_iso) \
                    .execute()

            # MODIFICATION TRANSPORT
            elif (
                existe
                and st.session_state.edit_mode
                and val
                and changer_transport
            ):

                supabase.table("trajets") \
                    .update({
                        "transport": transport_global,
                        "validated": False
                    }) \
                    .eq("user_id", cible) \
                    .eq("jour", jour_iso) \
                    .execute()

        st.session_state.edit_mode = False
        st.success("Encodage enregistré.")
        st.rerun()

    # ==================================================
    # ENVOI POUR VALIDATION
    # ==================================================
    if not is_admin and not st.session_state.edit_mode:

        if st.button("📤 Envoyer pour validation"):

            supabase.table("trajets") \
                .update({"sent_for_validation": True}) \
                .eq("user_id", cible) \
                .gte("jour", periode_start.isoformat()) \
                .lte("jour", periode_end.isoformat()) \
                .execute()

            st.success("Période envoyée pour validation.")
            st.rerun()

if menu == "Utilisateurs":

    st.header("Gestion des utilisateurs")
    st.divider()

    # ==================================================
    # RÉCUPÉRATION DES UTILISATEURS
    # ==================================================
    res_users = (
        supabase
        .table("users")
        .select("id, nom, prenom, login, km, is_admin")
        .order("nom")
        .execute()
    )

    users = res_users.data or []

    # ==================================================
    # CRÉATION UTILISATEUR
    # ==================================================
    st.subheader("➕ Créer un utilisateur")

    with st.form("form_create_user"):
        nom_u = st.text_input("Nom")
        prenom_u = st.text_input("Prénom")
        login_u = st.text_input("Login")
        km_u = st.number_input("Kilomètres domicile-travail", min_value=0.0)
        pwd_u = st.text_input("Mot de passe initial", type="password")
        is_admin_u = st.checkbox("Administrateur")

        submit_create = st.form_submit_button("Créer l'utilisateur")

        if submit_create:
            if not login_u or not pwd_u:
                st.error("Login et mot de passe obligatoires.")
            else:
                hpwd = bcrypt.hashpw(
                    pwd_u.encode(),
                    bcrypt.gensalt()
                ).decode()

                supabase.table("users").insert({
                    "nom": nom_u.strip(),
                    "prenom": prenom_u.strip(),
                    "login": login_u.lower().strip(),
                    "password": hpwd,
                    "km": float(km_u),
                    "is_admin": bool(is_admin_u),
                    "must_change_pwd": True
                }).execute()

                st.success("Utilisateur créé.")
                st.rerun()

    st.divider()

# ==================================================
# MODIFICATION / SUPPRESSION UTILISATEUR
# ==================================================
if is_admin:

    st.subheader("✏️ Modifier ou supprimer un utilisateur")

    users = locals().get("users", [])

    if not users:
        st.info("Aucun utilisateur disponible.")
        st.stop()

    user_labels = {
        f"{u.get('prenom','')} {u.get('nom','')} ({u.get('login','?')})": u
        for u in users
    }

    selected_user_label = st.selectbox(
        "Utilisateur",
        list(user_labels.keys()),
        key="select_user_admin_unique"
    )

    user = user_labels[selected_user_label]

    with st.form("form_edit_user"):

        nom_e = st.text_input("Nom", value=user.get("nom", ""))
        prenom_e = st.text_input("Prénom", value=user.get("prenom", ""))
        login_e = st.text_input("Login", value=user.get("login", ""))

        km_e = st.number_input(
            "Kilomètres domicile-travail",
            min_value=0.0,
            value=float(user.get("km", 0))
        )

        is_admin_e = st.checkbox(
            "Administrateur",
            value=bool(user.get("is_admin", False))
        )

        st.divider()

        st.markdown("### 🔐 Gestion du mot de passe")

        new_pwd = st.text_input(
            "Nouveau mot de passe",
            type="password"
        )

        force_change = st.checkbox(
            "Forcer le changement au prochain login",
            value=True
        )

        reset_pwd = st.checkbox("🔁 Réinitialiser à '1234'")

        st.divider()

        col1, col2 = st.columns(2)
        save = col1.form_submit_button("💾 Enregistrer")
        delete = col2.form_submit_button("🗑️ Supprimer")

        if save:

            update_data = {
                "nom": nom_e.strip(),
                "prenom": prenom_e.strip(),
                "login": login_e.lower().strip(),
                "km": float(km_e),
                "is_admin": bool(is_admin_e)
            }

            if reset_pwd:
                hpwd = bcrypt.hashpw("1234".encode(), bcrypt.gensalt()).decode()
                update_data["password"] = hpwd
                update_data["must_change_pwd"] = True

            elif new_pwd:
                hpwd = bcrypt.hashpw(new_pwd.encode(), bcrypt.gensalt()).decode()
                update_data["password"] = hpwd
                update_data["must_change_pwd"] = force_change

            supabase.table("users") \
                .update(update_data) \
                .eq("id", user["id"]) \
                .execute()

            st.success("Utilisateur modifié.")
            st.rerun()

        if delete:

            if user["id"] == uid:
                st.error("Impossible de supprimer votre propre compte.")
                st.stop()

            supabase.table("users") \
                .delete() \
                .eq("id", user["id"]) \
                .execute()

            st.warning("Utilisateur supprimé.")
            st.rerun()
# ==================================================
# IMPORT UTILISATEURS (EXCEL)
# ==================================================
if is_admin:

    st.subheader("📥 Import utilisateurs (Excel)")

    # ===== MODELE =====
    modele = pd.DataFrame(
        columns=["nom", "prenom", "login", "km", "password", "is_admin"]
    )

    buf_tpl = io.BytesIO()
    modele.to_excel(buf_tpl, index=False)
    buf_tpl.seek(0)

    # ===== DOWNLOAD MODELE (hors form) =====
    st.download_button(
        "📄 Télécharger le modèle Excel",
        buf_tpl,
        file_name="modele_utilisateurs.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        key="download_users_template"
    )

    st.divider()

    # ===== FORMULAIRE =====
    with st.form("form_import_users"):

        file = st.file_uploader(
            "Fichier Excel",
            type="xlsx"
        )

        submit_import = st.form_submit_button("Importer")

        if submit_import:
            if not file:
                st.warning("Veuillez sélectionner un fichier Excel.")
            else:
                df = pd.read_excel(file)

                colonnes = {
                    "nom", "prenom", "login",
                    "km", "password", "is_admin"
                }

                if not colonnes.issubset(df.columns):
                    st.error(
                        "Colonnes requises : "
                        + ", ".join(colonnes)
                    )
                else:
                    ajoutes, erreurs = 0, 0

                    for _, r in df.iterrows():
                        try:
                            hpwd = bcrypt.hashpw(
                                str(r["password"]).encode(),
                                bcrypt.gensalt()
                            ).decode()

                            supabase.table("users").insert({
                                "nom": str(r["nom"]).strip(),
                                "prenom": str(r["prenom"]).strip(),
                                "login": str(r["login"]).lower().strip(),
                                "password": hpwd,
                                "km": float(r["km"]),
                                "is_admin": bool(r["is_admin"]),
                                "must_change_pwd": True
                            }).execute()

                            ajoutes += 1

                        except Exception:
                            erreurs += 1

                    st.success(
                        f"Import terminé : {ajoutes} ajouté(s), "
                        f"{erreurs} erreur(s)."
                    )

                    st.rerun()
# ==================================================
# EXPORT UTILISATEURS
# ==================================================
if is_admin:

    st.subheader("📊 Exporter les utilisateurs")

    # ============================
    # RÉCUPÉRATION DONNÉES
    # ============================
    res_export = (
        supabase
        .table("users")
        .select("nom, prenom, login, km, is_admin")
        .order("nom")
        .execute()
    )

    users_data = res_export.data or []

    if not users_data:
        st.info("Aucun utilisateur à exporter.")
        st.stop()

    # ============================
    # DATAFRAME
    # ============================
    df_export = pd.DataFrame(users_data)

    df_export = df_export.rename(columns={
        "nom": "Nom",
        "prenom": "Prénom",
        "login": "Login",
        "km": "KM",
        "is_admin": "Admin"
    })

    # ============================
    # APERÇU
    # ============================
    st.dataframe(df_export, use_container_width=True)

    # ============================
    # EXPORT EXCEL
    # ============================
    buffer = io.BytesIO()

    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        df_export.to_excel(writer, index=False, sheet_name="Utilisateurs")

    buffer.seek(0)

    # ============================
    # DOWNLOAD
    # ============================
    st.download_button(
        "📥 Télécharger la liste des utilisateurs",
        buffer,
        file_name="liste_utilisateurs.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        key="export_users"
    )

    # ==================================================
    # VALIDATION GLOBALE (ADMIN)
    # ==================================================
    if is_admin:
        st.subheader("Validation globale")

        if st.button("✅ Valider tous les utilisateurs", key="btn_validate_all"):
            res_users = (
                supabase
                .table("users")
                .select("id, km")
                .neq("login", "admin")
                .execute()
            )

            if not res_users.data:
                st.warning("Aucun utilisateur à valider.")
            else:
                for u in res_users.data:
                    valider_mois(
                        user_id=u["id"],
                        annee=annee,
                        mois=mois_num,
                        km=u["km"]
                    )

                st.success("Tous les utilisateurs ont été validés.")
                st.rerun()

    st.divider()

    # ==================================================
    # VALIDATION INDIVIDUELLE
    # ==================================================
    st.subheader("Validation par utilisateur")

    res_users = (
        supabase
        .table("users")
        .select("id, prenom, nom, km")
        .neq("login", "admin")
        .order("nom")
        .execute()
    )

    if not res_users.data:
        st.info("Aucun utilisateur disponible.")
        st.stop()

    labels = ["— Sélectionner un utilisateur —"]
    user_map = {}

    for u in res_users.data:
        label = f"{u['prenom']} {u['nom']}"
        labels.append(label)
        user_map[label] = u

    selected_label = st.selectbox(
        "Utilisateur",
        labels,
        key="select_user_validation_unique"
    )

    if selected_label == labels[0]:
        st.stop()

    # ==================================================
    # CONTEXTE UTILISATEUR
    # ==================================================
    user = user_map[selected_label]
    user_id = user["id"]
    km_user = float(user["km"])

    # ==================================================
    # DÉTAIL DES JOURS DU MOIS COURANT (01 → 20)
    # ==================================================
    start = date(annee, mois_num, 1)
    end = date(annee, mois_num, 20)

    res_jours = (
        supabase
        .table("trajets")
        .select("jour, transport")
        .eq("user_id", user_id)
        .gte("jour", start.isoformat())
        .lte("jour", end.isoformat())
        .order("jour")
        .execute()
    )

    if res_jours.data:
        df = pd.DataFrame(res_jours.data)
        df["Jour"] = pd.to_datetime(df["jour"]).dt.strftime("%d/%m/%Y")
        df["KM"] = km_user
        df["Taux"] = df["transport"].map(TAUX)
        df["Indemnité"] = df["KM"] * df["Taux"]

        st.subheader("Détail des jours (01 → 20)")
        st.dataframe(
            df[["Jour", "transport", "KM", "Indemnité"]],
            use_container_width=True
        )
    else:
        st.warning("Aucun jour encodé pour ce mois.")

    st.divider()

    # ==================================================
    # SIMULATION AVANT VALIDATION
    # ==================================================
    brut, plafonne = total_mois_courant(
        user_id,
        annee,
        mois_num,
        km_user
    )

    regul, mois_prec = calcul_regularisation_mois_precedent(
        user_id,
        f"{annee}-{mois_num:02d}",
        plafonne
    )

    total_simule = round(plafonne + regul, 2)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Montant brut (mois)", f"{brut:.2f} €")
    c2.metric("Plafonné (mois)", f"{plafonne:.2f} €")
    c3.metric(
        "Régularisation mois précédent",
        f"{regul:+.2f} €"
    )
    c4.metric("Total payé", f"{total_simule:.2f} €")

    st.divider()

    # ==================================================
    # ACTIONS
    # ==================================================
    col1, col2 = st.columns(2)

    with col1:
        if st.button("✅ Valider le mois", key="btn_validate_single"):
            resultat = valider_mois(
                user_id=user_id,
                annee=annee,
                mois=mois_num,
                km=km_user
            )

            st.success(
                f"Mois validé — "
                f"Total payé : {resultat['total_paye']:.2f} € "
                f"(dont régularisation {resultat['regularisation']:+.2f} €)"
            )
            st.rerun()

    with col2:
        st.caption(
            "ℹ️ Le mois courant complète automatiquement le mois précédent "
            "si le plafond n’était pas atteint."
        )
if menu == "Exports":
    st.header("Export mensuel des indemnités")

    mois_str = f"{annee}-{mois_num:02d}"

    # ============================
    # VALIDATIONS DU MOIS
    # ============================
    validations = (
        supabase
        .table("validations")
        .select(
            "user_id, brut, plafonne, exported, "
            "modified_after_validation, revalidated"
        )
        .eq("mois", mois_str)
        .execute()
        .data
    )

    if not validations:
        st.info("Aucune validation pour ce mois.")
        st.stop()

    # ============================
    # VERROU EXPORT UNIQUE
    # ============================
    if all(v.get("exported", False) for v in validations):
        st.warning("⚠️ L’export pour ce mois a déjà été généré.")
        st.stop()

    user_ids = [v["user_id"] for v in validations]

    # ============================
    # RÉGULARISATIONS
    # ============================
    regs = (
        supabase
        .table("regularisations")
        .select("user_id, montant")
        .eq("mois_cible", mois_str)
        .execute()
        .data
    )

    reg_map = {}
    for r in regs:
        reg_map.setdefault(r["user_id"], 0.0)
        reg_map[r["user_id"]] += float(r["montant"])

    # ============================
    # INFOS UTILISATEURS
    # ============================
    users = (
        supabase
        .table("users")
        .select("id, nom, prenom, km")
        .in_("id", user_ids)
        .execute()
        .data
    )

    user_map = {u["id"]: u for u in users}

    # ============================
    # COMPTAGE JOURS PAR TRANSPORT
    # ============================
    trajets = (
        supabase
        .table("trajets")
        .select("user_id, transport")
        .in_("user_id", user_ids)
        .gte("jour", periode_start.isoformat())
        .lte("jour", periode_end.isoformat())
        .execute()
        .data
    )

    df_trajets = pd.DataFrame(trajets)

    if not df_trajets.empty:
        counts = (
            df_trajets
            .pivot_table(
                index="user_id",
                columns="transport",
                values="transport",
                aggfunc="count",
                fill_value=0
            )
            .reset_index()
        )
    else:
        counts = pd.DataFrame(columns=["user_id"])

    # ============================
    # CONSTRUCTION EXPORT
    # ============================
    lignes = []

    for v in validations:
        uid = v["user_id"]
        regul = reg_map.get(uid, 0.0)

        ligne = {
            "Nom": user_map[uid]["nom"],
            "Prénom": user_map[uid]["prenom"],
            "KM": user_map[uid]["km"],
            "Indemnité brute (€)": round(v["brut"], 2),
            "Indemnité plafonnée (€)": round(v["plafonne"], 2),
            "Régularisation (€)": round(regul, 2),
            "Total payé (€)": round(v["plafonne"] + regul, 2),
            "Modifié après validation": "OUI" if v.get("modified_after_validation") else "NON",
            "Revalidé": "OUI" if v.get("revalidated") else "NON",
        }

        if uid in counts["user_id"].values:
            row = counts[counts["user_id"] == uid].iloc[0]
            for t in TRANSPORTS:
                ligne[f"Jours {t}"] = int(row.get(t, 0))
        else:
            for t in TRANSPORTS:
                ligne[f"Jours {t}"] = 0

        lignes.append(ligne)

    df = pd.DataFrame(lignes)

    st.subheader("Aperçu des données exportées")
    st.dataframe(df, use_container_width=True)

    # ============================
    # EXPORT EXCEL
    # ============================
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Indemnités")

    buffer.seek(0)

    if st.download_button(
        "📥 Télécharger l’export mensuel",
        buffer,
        f"indemnites_{mois_str}.xlsx"
    ):
        supabase.table("validations") \
            .update({"exported": True}) \
            .eq("mois", mois_str) \
            .execute()


if menu == "Historique":
    st.header("Historique de mes encodages")

    trajets = (
        supabase
        .table("trajets")
        .select("jour, transport")
        .eq("user_id", uid)
        .execute()
        .data
    )

    if not trajets:
        st.info("Aucun encodage trouvé.")
        st.stop()

    df = pd.DataFrame(trajets)
    df["mois"] = df["jour"].str[:7]

    pivot = df.pivot_table(
        index="mois",
        columns="transport",
        values="jour",
        aggfunc="count",
        fill_value=0
    ).reset_index()

    for t in TRANSPORTS:
        if t not in pivot.columns:
            pivot[t] = 0

    # ============================
    # RÉCUP VALIDATIONS
    # ============================
    validations = (
        supabase
        .table("validations")
        .select("mois, plafonne")
        .eq("user_id", uid)
        .execute()
        .data
    )

    val_map = {v["mois"]: float(v["plafonne"]) for v in validations}

    # ============================
    # RÉCUP REGULARISATIONS
    # ============================
    regs = (
        supabase
        .table("regularisations")
        .select("mois_cible, montant")
        .eq("user_id", uid)
        .execute()
        .data
    )

    reg_map = {}
    for r in regs:
        reg_map.setdefault(r["mois_cible"], 0.0)
        reg_map[r["mois_cible"]] += float(r["montant"])

    # ============================
    # MONTANTS
    # ============================
    pivot["Payé pour ce mois (€)"] = pivot["mois"].map(val_map).fillna(0)

    pivot["Régularisation reçue (€)"] = pivot["mois"].map(reg_map).fillna(0)

    pivot["Total reçu (€)"] = (
        pivot["Payé pour ce mois (€)"] +
        pivot["Régularisation reçue (€)"]
    )

    # ============================
    # STATUT
    # ============================
    pivot["Statut"] = pivot["mois"].apply(
        lambda m: "✅ Validé" if m in val_map else "⏳ En attente"
    )

    # ============================
    # AFFICHAGE
    # ============================
    st.dataframe(pivot, use_container_width=True)