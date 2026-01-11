import streamlit as st
import calendar, io
import pandas as pd
import bcrypt
from datetime import date
from supabase import create_client, Client
import os

# ================= SUPABASE =================
SUPABASE_URL = st.secrets.get("SUPABASE_URL")
SUPABASE_KEY = st.secrets.get("SUPABASE_ANON_KEY")
if not SUPABASE_URL or not SUPABASE_KEY:
    st.error("❌ Supabase non configuré (secrets manquants)")
    st.stop()

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
# ================= CONFIG =================
TRANSPORTS = ["Voiture", "Vélo", "Transport"]
TAUX = {"Voiture": 0.10, "Vélo": 0.00, "Transport": 0.00}
PLAFOND_MENSUEL = 60.0

JOURS_FR = ["Lundi","Mardi","Mercredi","Jeudi","Vendredi","Samedi","Dimanche"]
MOIS_FR = [
    "Janvier","Février","Mars","Avril","Mai","Juin",
    "Juillet","Août","Septembre","Octobre","Novembre","Décembre"
]

# ================= SUPABASE HELPERS =================
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

# ================= CALCUL MONTANT MOIS =================
def calcul_montant_mois(user_id, ym, km):
    rows = (
        supabase
        .table("trajets")
        .select("transport")
        .eq("user_id", user_id)
        .like("jour", f"{ym}%")
        .execute()
        .data
    )

    if not rows:
        return 0.0

    df = pd.DataFrame(rows)
    df["taux"] = df["transport"].map(TAUX)
    total = (df["taux"] * km).sum()

    return round(min(total, PLAFOND_MENSUEL), 2)

# ================= RÉGULARISATIONS =================
def total_regularisations(user_id, ym):
    rows = (
        supabase
        .table("regularisations")
        .select("montant")
        .eq("user_id", user_id)
        .eq("mois_cible", ym)
        .execute()
        .data
    )

    if not rows:
        return 0.0

    return round(sum(r["montant"] for r in rows), 2)
# ================= INIT ADMIN (SUPABASE) =================



# ================= CALCUL MOIS =================
def total_mois(user_id, ym, km):
    rows = (
        supabase
        .table("trajets")
        .select("transport")
        .eq("user_id", user_id)
        .like("jour", f"{ym}%")
        .execute()
        .data
    )

    if not rows:
        return 0.0, 0.0

    df = pd.DataFrame(rows)
    brut = (df["transport"].map(TAUX) * km).sum()
    plafonne = min(brut, PLAFOND_MENSUEL)

    return round(brut, 2), round(plafonne, 2)

# ================= RÉGULARISATION =================
def creer_regularisation_si_necessaire(
    user_id,
    mois_source,
    ancien_brut,
    ancien_plafonne,
    nouveau_brut,
    nouveau_plafonne
):
    # CAS AUGMENTATION
    if nouveau_plafonne > ancien_plafonne:
        if ancien_plafonne >= PLAFOND_MENSUEL:
            return
        diff = nouveau_plafonne - ancien_plafonne

    # CAS DIMINUTION
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

# ================= MONTANT FINAL =================
def montant_final_paye(user_id, ym, km):
    brut, plafonne = total_mois(user_id, ym, km)
    regul = total_regularisations(user_id, ym)

    total = round(plafonne + regul, 2)

    return {
        "brut": round(brut, 2),
        "plafonne": round(plafonne, 2),
        "regularisation": round(regul, 2),
        "total_paye": total,
        "plafond_atteint": brut > PLAFOND_MENSUEL
    }
# ================= AUTH (SUPABASE) =================
def login_user(login: str, pwd: str):
    try:
        res = (
            supabase
            .table("users")
            .select(
                "id, nom, prenom, login, password, km, is_admin, must_change_pwd"
            )
            .eq("login", login.lower().strip())
            .limit(1)
            .execute()
        )
    except Exception as e:
        st.error("Erreur accès base (RLS / Supabase)")
        st.stop()

    if not res.data:
        return None

    user = res.data[0]

    try:
        ok = bcrypt.checkpw(
            pwd.encode(),
            user["password"].encode()
        )
    except Exception:
        return None

    return user if ok else None





# ================= SESSION STATE INIT =================
if "user" not in st.session_state:
    st.session_state.user = None

if "edit_mode" not in st.session_state:
    st.session_state.edit_mode = False

if "jours_selectionnes" not in st.session_state:
    st.session_state.jours_selectionnes = set()


# ================= LOGIN =================
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


# ================= USER CONTEXT =================
uid = st.session_state.user["id"]
nom = st.session_state.user["nom"]
prenom = st.session_state.user["prenom"]
login = st.session_state.user["login"]
km = st.session_state.user["km"]
is_admin = st.session_state.user["is_admin"]
must_change_pwd = st.session_state.user["must_change_pwd"]


# ================= UI INIT =================
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


# ================= FORCE PASSWORD CHANGE =================
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


# ================= MENU =================
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
# ================= DATE =================
annee = mois = mois_num = ym = None

if menu in ["Encodage", "Validation", "Exports", "Historique"]:
    today = date.today()

    annee = st.selectbox(
        "Année",
        range(today.year - 1, today.year + 3),
        index=1,
        key="select_annee"
    )

    mois = st.selectbox(
        "Mois",
        MOIS_FR,
        index=today.month - 1,
        key="select_mois"
    )

    mois_num = MOIS_FR.index(mois) + 1
    ym = f"{annee}-{mois_num:02d}"


# ================= CALENDRIER (SUPABASE) =================
def calendrier(user_id, admin=False):

    rows = (
        supabase
        .table("trajets")
        .select("jour, transport, validated, sent_for_validation")
        .eq("user_id", user_id)
        .like("jour", f"{ym}%")
        .execute()
        .data
    )

    data = {
        int(r["jour"][-2:]): {
            "transport": r["transport"],
            "validated": r["validated"] == 1,
            "sent": r.get("sent_for_validation", 0) == 1
        }
        for r in rows
    }

    weeks = calendar.monthcalendar(annee, mois_num)
    jours = []

    st.markdown(f"""
**Légende – {mois} {annee}**  
🚗 Voiture &nbsp; 🚲 Vélo &nbsp; 🚌 Transport  
✏️ Sélectionné (édition) &nbsp; 🔒 Verrouillé  
⛔ Week-end / envoyé = verrouillé  
⚠️ Mois validé : verrouillé utilisateur, **admin autorisé**
""")

    for week in weeks:
        cols = st.columns(7)

        for i, d in enumerate(week):
            with cols[i]:
                if d == 0:
                    st.write("")
                    continue

                wd = calendar.weekday(annee, mois_num, d)
                is_weekend = wd >= 5
                label = f"{JOURS_FR[wd][:2]} {d:02d}/{mois_num:02d}"

                existe = d in data
                validated = data[d]["validated"] if existe else False
                sent = data[d]["sent"] if existe else False

                # 🔒 verrou logique correct
                locked = (
                    is_weekend
                    or sent
                    or (validated and not admin)
                )

                # ================= WEEK-END =================
                if is_weekend:
                    st.checkbox(
                        label,
                        disabled=True,
                        key=f"we_{user_id}_{ym}_{d}"
                    )
                    st.caption("⛔ Week-end")
                    val = False

                # ================= JOUR EXISTANT =================
                elif existe:
                    icon = {
                        "Voiture": "🚗",
                        "Vélo": "🚲",
                        "Transport": "🚌"
                    }.get(data[d]["transport"], "❓")

                    status = "✅" if validated else "⏳" if sent else ""

                    # --- consultation ---
                    if not st.session_state.edit_mode:
                        st.checkbox(
                            label,
                            value=True,
                            disabled=True,
                            key=f"exist_{user_id}_{ym}_{d}"
                        )
                        st.caption(f"{icon} {data[d]['transport']} {status}")
                        val = True

                    # --- édition ---
                    else:
                        selected = d in st.session_state.jours_selectionnes

                        toggle = st.checkbox(
                            f"Sélectionner {label}",
                            value=selected,
                            disabled=locked,
                            key=f"select_{user_id}_{ym}_{d}"
                        )

                        if toggle:
                            st.session_state.jours_selectionnes.add(d)
                            st.caption(f"✏️ {icon} {data[d]['transport']}")
                        else:
                            st.session_state.jours_selectionnes.discard(d)
                            st.caption(f"🔒 {icon} {data[d]['transport']}")

                        val = True

                # ================= NOUVEAU JOUR =================
                else:
                    val = st.checkbox(
                        label,
                        value=False,
                        disabled=is_weekend,
                        key=f"new_{user_id}_{ym}_{d}"
                    )
                    if val:
                        st.caption("➕ Nouveau")

                if not is_weekend:
                    jours.append((d, val, existe, validated, sent))

    return jours
# ================= UTILISATEURS =================
# ================= UTILISATEURS =================
# ================= UTILISATEURS =================
if menu == "Utilisateurs":
    st.header("Gestion des utilisateurs")

    # ========= RÉCUPÉRATION DES UTILISATEURS =========
    res = (
        supabase
        .table("users")
        .select("id, nom, prenom, login, km, is_admin")
        .order("nom")
        .execute()
    )
    users = res.data or []

    # ========= CRÉATION UTILISATEUR =========
    st.subheader("➕ Créer un utilisateur")

    with st.form(key="admin_create_user_form"):
        nom_u = st.text_input("Nom")
        prenom_u = st.text_input("Prénom")
        login_u = st.text_input("Login")
        km_u = st.number_input("Kilomètres domicile-travail", min_value=0.0)
        pwd_u = st.text_input("Mot de passe initial", type="password")
        is_admin_u = st.checkbox("Administrateur")

        submit_create = st.form_submit_button("Créer")

        if submit_create:
            if not login_u or not pwd_u:
                st.error("Login et mot de passe obligatoires")
            else:
                try:
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

                    st.success("Utilisateur créé")
                    st.rerun()

                except Exception as e:
                    st.error(f"Erreur création utilisateur : {e}")

    st.divider()

    # ========= MODIFICATION / SUPPRESSION =========
    st.subheader("✏️ Modifier / Supprimer un utilisateur")

    if not users:
        st.info("Aucun utilisateur disponible")
    else:
        user_map = {
            f"{u['prenom']} {u['nom']} ({u['login']})": u
            for u in users
        }

        selected_label = st.selectbox(
            "Utilisateur",
            list(user_map.keys()),
            key="admin_user_select"
        )

        u = user_map[selected_label]

        with st.form(key="admin_edit_user_form"):
            nom_e = st.text_input("Nom", value=u["nom"])
            prenom_e = st.text_input("Prénom", value=u["prenom"])
            login_e = st.text_input("Login", value=u["login"])
            km_e = st.number_input(
                "Kilomètres domicile-travail",
                min_value=0.0,
                value=float(u["km"])
            )
            is_admin_e = st.checkbox(
                "Administrateur",
                value=bool(u["is_admin"])
            )

            col1, col2 = st.columns(2)
            save = col1.form_submit_button("💾 Enregistrer")
            delete = col2.form_submit_button("🗑️ Supprimer")

            if save:
                try:
                    supabase.table("users") \
                        .update({
                            "nom": nom_e.strip(),
                            "prenom": prenom_e.strip(),
                            "login": login_e.lower().strip(),
                            "km": float(km_e),
                            "is_admin": bool(is_admin_e)
                        }) \
                        .eq("id", u["id"]) \
                        .execute()

                    st.success("Utilisateur modifié")
                    st.rerun()

                except Exception as e:
                    st.error(f"Erreur modification : {e}")

            if delete:
                try:
                    supabase.table("users") \
                        .delete() \
                        .eq("id", u["id"]) \
                        .execute()

                    st.warning("Utilisateur supprimé")
                    st.rerun()

                except Exception as e:
                    st.error(f"Erreur suppression : {e}")

    st.divider()

    # ========= IMPORT UTILISATEURS (EXCEL) =========
    st.subheader("📥 Import utilisateurs (Excel)")

    modele = pd.DataFrame(
        columns=["nom", "prenom", "login", "km", "password", "is_admin"]
    )
    buf_tpl = io.BytesIO()
    modele.to_excel(buf_tpl, index=False)
    buf_tpl.seek(0)

    st.download_button(
        "📄 Télécharger le template Excel",
        buf_tpl,
        file_name="modele_utilisateurs.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        key="admin_users_template_download"
    )

    with st.form(key="admin_import_users_form"):
        file = st.file_uploader(
            "Sélectionner le fichier Excel",
            type="xlsx"
        )
        submit_import = st.form_submit_button("📥 Importer les utilisateurs")

        if submit_import:
            if not file:
                st.warning("Veuillez sélectionner un fichier Excel.")
            else:
                try:
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

                except Exception as e:
                    st.error(f"Erreur import : {e}")

    st.divider()

    # ========= EXPORT UTILISATEURS (ADMIN SEULEMENT) =========
    st.subheader("📊 Exporter la liste des utilisateurs")

    response = (
        supabase
        .table("users")
        .select("nom, prenom, login, km, is_admin")
        .order("nom")
        .execute()
    )

    if response.data:
        df_users = pd.DataFrame(response.data)

        buf_users = io.BytesIO()
        df_users.to_excel(buf_users, index=False)
        buf_users.seek(0)

        st.download_button(
            label="📥 Télécharger la liste des utilisateurs (Excel)",
            data=buf_users,
            file_name="liste_utilisateurs.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            key="admin_users_export_only"
        )
    else:
        st.info("Aucun utilisateur à exporter.")

# ================= ENCODAGE =================
# ================= ENCODAGE =================
save_clicked = False
send_clicked = False

if menu == "Encodage":
    st.header("Encodage des trajets")

    # ===== Sélection utilisateur (admin) =====
    cible = uid
    if is_admin:
        users = (
            supabase
            .table("users")
            .select("id, prenom, nom")
            .neq("login", "admin")
            .order("nom")
            .execute()
            .data
        )

        u = st.selectbox(
            "Utilisateur",
            users,
            format_func=lambda x: f"{x['prenom']} {x['nom']}",
            key="encodage_user_select"
        )
        cible = u["id"]

    # ===== Transport global =====
    transport_global = st.selectbox(
        "Moyen de transport pour les NOUVEAUX jours",
        TRANSPORTS
    )

    # ===== Boutons =====
    col1, col2, col3 = st.columns([1, 1, 2])

    with col1:
        btn_modifier = st.button("✏️ Modifier l'encodage")

    with col2:
        save_clicked = st.button("💾 Enregistrer")

    with col3:
        send_clicked = (
            not is_admin
            and not st.session_state.edit_mode
            and st.button("📤 Envoyer pour validation")
        )

    # ===== Calendrier =====
    jours = calendrier(cible, admin=is_admin)

    # ===== Détection mois validé =====
    mois_valide = any(validated for _, _, _, validated, _ in jours)

    # ===== Blocage TOTAL utilisateur si mois validé =====
    if mois_valide and not is_admin:
        st.info("🔒 Ce mois est validé. Consultation uniquement.")
        st.session_state.edit_mode = False
        st.stop()

    # ===== Activation édition =====
    if btn_modifier:
        st.session_state.edit_mode = True

    # ===== Suppression =====
    if st.session_state.edit_mode and st.session_state.jours_selectionnes:
        if st.button("🗑️ Supprimer les jours sélectionnés"):
            for d in st.session_state.jours_selectionnes:
                jour = f"{ym}-{d:02d}"
                supabase.table("trajets") \
                    .delete() \
                    .eq("user_id", cible) \
                    .eq("jour", jour) \
                    .execute()

            st.session_state.jours_selectionnes.clear()
            st.session_state.edit_mode = False
            st.success("Jour(s) supprimé(s)")
            st.rerun()

    # ===== Enregistrement =====
    if save_clicked:
        for d, val, existe, validated, sent in jours:
            jour = f"{ym}-{d:02d}"

            # ➕ Ajout
            if not existe and val:
                supabase.table("trajets").insert({
                    "user_id": cible,
                    "jour": jour,
                    "transport": transport_global,
                    "validated": 0,
                    "sent_for_validation": 0
                }).execute()

            # ✏️ Modification / suppression
            elif existe and st.session_state.edit_mode and d in st.session_state.jours_selectionnes:
                if not val:
                    supabase.table("trajets") \
                        .delete() \
                        .eq("user_id", cible) \
                        .eq("jour", jour) \
                        .execute()
                else:
                    supabase.table("trajets") \
                        .update({
                            "transport": transport_global,
                            "validated": 0
                        }) \
                        .eq("user_id", cible) \
                        .eq("jour", jour) \
                        .execute()

        st.session_state.edit_mode = False
        st.session_state.jours_selectionnes.clear()
        st.success("Encodage enregistré")
        st.rerun()

# ===== Envoi validation =====
if send_clicked:
    supabase.table("trajets") \
        .update({"sent_for_validation": True}) \
        .eq("user_id", cible) \
        .like("jour", f"{ym}%") \
        .execute()

    st.success("Mois envoyé pour validation")
    st.rerun()

    supabase.table("trajets") \
        .update({"sent_for_validation": True}) \
        .eq("user_id", cible) \
        .like("jour", f"{ym}%") \
        .execute()

    st.success("Mois envoyé pour validation")
    st.rerun()
  





# ===================== ENREGISTREMENT =====================
if save_clicked:
    for d, val, existe, validated, sent in jours:
        jour = f"{ym}-{d:02d}"

        # ➕ AJOUT (jours non existants)
        if not existe and val:
            supabase.table("trajets").insert({
                "user_id": cible,
                "jour": jour,
                "transport": transport_global,
                "validated": False,
                "sent_for_validation": False
            }).execute()

        # ✏️ MODIFICATION / SUPPRESSION
        elif existe and st.session_state.edit_mode:
            if d not in st.session_state.jours_selectionnes:
                continue  # 🔒 jour ignoré volontairement

            if not val:
                supabase.table("trajets") \
                    .delete() \
                    .eq("user_id", cible) \
                    .eq("jour", jour) \
                    .execute()
            else:
                supabase.table("trajets") \
                    .update({
                        "transport": transport_global,
                        "validated": False
                    }) \
                    .eq("user_id", cible) \
                    .eq("jour", jour) \
                    .execute()

    # reset propre
    st.session_state.edit_mode = False
    st.session_state.jours_selectionnes.clear()
    st.success("Encodage enregistré")
    st.rerun()


# ================= VALIDATION =================
# ================= VALIDATION =================
if menu == "Validation":
    st.header("Validation des indemnités")
    st.divider()

    # ==================================================
    # VALIDATION GLOBALE (ADMIN UNIQUEMENT)
    # ==================================================
    st.subheader("Validation globale")

    if is_admin:
        if st.button("✅ Valider tous les utilisateurs", key="validate_all_users"):

            res_users = (
                supabase
                .table("users")
                .select("id, km")
                .neq("login", "admin")
                .execute()
            )

            if not res_users.data:
                st.warning("Aucun utilisateur à valider.")
                st.stop()

            for u in res_users.data:
                uid_u = u["id"]
                km_u = u["km"]

                brut, plafonne = total_mois(uid_u, ym, km_u)

                # Supprimer validation existante
                supabase.table("validations") \
                    .delete() \
                    .eq("user_id", uid_u) \
                    .eq("mois", ym) \
                    .execute()

                # Créer validation
                supabase.table("validations").insert({
                    "user_id": uid_u,
                    "mois": ym,
                    "km_utilise": km_u,
                    "brut": brut,
                    "plafonne": plafonne
                }).execute()

                # Verrouiller trajets
                supabase.table("trajets") \
                    .update({"validated": 1}) \
                    .eq("user_id", uid_u) \
                    .like("jour", f"{ym}-%") \
                    .execute()

            st.success("Tous les utilisateurs ont été validés")
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

    selection = st.selectbox("Utilisateur", labels)

    if selection == labels[0]:
        st.stop()

    # ===== Contexte utilisateur =====
    user = user_map[selection]
    user_id = user["id"]
    km_user = float(user["km"])

    # ===== Ancienne validation ? =====
    ancienne = None
    ancien_brut = ancien_plafonne = ancien_km = ancienne_date = None

    res_old = (
        supabase
        .table("validations")
        .select("brut, plafonne, km_utilise, validated_at")
        .eq("user_id", user_id)
        .eq("mois", ym)
        .execute()
    )

    if res_old.data:
        ancienne = res_old.data[0]
        ancien_brut = ancienne["brut"]
        ancien_plafonne = ancienne["plafonne"]
        ancien_km = ancienne["km_utilise"]
        ancienne_date = ancienne["validated_at"]

    km_utilise = ancien_km if ancien_km is not None else km_user

    # ===== Calculs =====
    montants = montant_final_paye(user_id, ym, km_utilise)

    brut_calcule = montants["brut"]
    plafonne_calcule = montants["plafonne"]
    regul = montants["regularisation"]
    total_verse = montants["total_paye"]

    # ===== Détail des jours =====
    res_jours = (
        supabase
        .table("trajets")
        .select("jour, transport")
        .eq("user_id", user_id)
        .like("jour", f"{ym}-%")
        .order("jour")
        .execute()
    )

    if res_jours.data:
        df = pd.DataFrame(res_jours.data)
        df["Jour"] = pd.to_datetime(df["jour"]).dt.strftime("%d/%m/%Y")
        df["KM"] = km_utilise
        df["Taux"] = df["transport"].map(TAUX)
        df["Indemnité"] = df["KM"] * df["Taux"]

        st.subheader("Détail des jours encodés")
        st.dataframe(
            df[["Jour", "transport", "KM", "Indemnité"]],
            use_container_width=True
        )
    else:
        st.warning("Aucun jour encodé pour ce mois.")

    st.divider()

    # ===== Synthèse =====
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Montant brut", f"{brut_calcule:.2f} €")
    c2.metric("Plafonné", f"{plafonne_calcule:.2f} €")
    c3.metric("Régularisation", f"{regul:+.2f} €")
    c4.metric("Total payé", f"{total_verse:.2f} €")

    if ancienne:
        delta = round(plafonne_calcule - ancien_plafonne, 2)
        st.caption(
            f"🕒 Validé le {ancienne_date} — "
            f"Ancien montant : {ancien_plafonne:.2f} € ({delta:+.2f} €)"
        )

    st.divider()

    # ===== Boutons =====
    colb1, colb2 = st.columns(2)

    # --- Validation initiale ---
    with colb1:
        if st.button("✅ Valider", disabled=ancienne is not None):
            supabase.table("validations").insert({
                "user_id": user_id,
                "mois": ym,
                "km_utilise": km_utilise,
                "brut": brut_calcule,
                "plafonne": plafonne_calcule
            }).execute()

            supabase.table("trajets") \
                .update({"validated": 1}) \
                .eq("user_id", user_id) \
                .like("jour", f"{ym}-%") \
                .execute()

            st.success("Mois validé")
            st.rerun()

    # --- Revalidation ---
    with colb2:
        if st.button("🔁 Revalider", disabled=ancienne is None):

            creer_regularisation_si_necessaire(
                user_id,
                ym,
                ancien_brut,
                ancien_plafonne,
                brut_calcule,
                plafonne_calcule
            )

            supabase.table("validations") \
                .update({
                    "brut": brut_calcule,
                    "plafonne": plafonne_calcule,
                    "validated_at": "now()"
                }) \
                .eq("user_id", user_id) \
                .eq("mois", ym) \
                .execute()

            st.success("Mois revalidé avec régularisation")
            st.rerun()

if menu == "Exports":
    st.header("Export mensuel des indemnités")

    trajets = supabase.table("trajets") \
        .select("user_id, transport") \
        .like("jour", f"{ym}%") \
        .execute() \
        .data

    if not trajets:
        st.info("Aucune donnée à exporter pour ce mois.")
        st.stop()

    user_ids = {t["user_id"] for t in trajets}

    users = supabase.table("users") \
        .select("id, nom, prenom, km") \
        .in_("id", list(user_ids)) \
        .execute() \
        .data

    lignes = []

    for u in users:
        uid_u = u["id"]
        km_user = u["km"]

        jours = {t: 0 for t in TRANSPORTS}
        for t in trajets:
            if t["user_id"] == uid_u:
                jours[t["transport"]] += 1

        montants = montant_final_paye(uid_u, ym, km_user)

        lignes.append({
            "Nom": u["nom"],
            "Prénom": u["prenom"],
            "KM": km_user,
            "Jours Voiture": jours["Voiture"],
            "Jours Vélo": jours["Vélo"],
            "Jours Transport": jours["Transport"],
            "Indemnité calculée (€)": montants["brut"],
            "Indemnité plafonnée (€)": montants["plafonne"],
            "Régularisation (€)": montants["regularisation"],
            "Indemnité réellement versée (€)": montants["total_paye"]
        })

    recap = pd.DataFrame(lignes)

    st.subheader("Aperçu des données exportées")
    st.dataframe(recap, width="stretch")

    buffer = io.BytesIO()
    nom_fichier = f"indemnites_{ym}.xlsx"

    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        recap.to_excel(writer, index=False, sheet_name="Indemnités")

    buffer.seek(0)

    st.download_button(
        "📥 Télécharger l’export mensuel",
        buffer,
        nom_fichier,
        key=f"btn_export_indemnites_{ym}"
)


if menu == "Historique":
    st.header("Historique de mes encodages")

    trajets = supabase.table("trajets") \
        .select("jour, transport, validated") \
        .eq("user_id", uid) \
        .execute() \
        .data

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

    pivot["Total calculé (€)"] = (
        pivot["Voiture"] * km * TAUX["Voiture"]
        + pivot["Vélo"] * km * TAUX["Vélo"]
        + pivot["Transport"] * km * TAUX["Transport"]
    )

    pivot["Total remboursé (€)"] = pivot["Total calculé (€)"].apply(
        lambda x: min(x, PLAFOND_MENSUEL)
    )

    pivot["Statut"] = df.groupby("mois")["validated"] \
        .max() \
        .apply(lambda x: "✅ Validé" if x else "⏳ En attente") \
        .values

    st.dataframe(
        pivot[[
            "mois",
            "Voiture",
            "Vélo",
            "Transport",
            "Total calculé (€)",
            "Total remboursé (€)",
            "Statut"
        ]],
        width="stretch"
    )
