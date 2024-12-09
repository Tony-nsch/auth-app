<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Utilisateur;
use App\Models\Log;
use App\Models\Reactivation;
use App\Http\Controllers\Email;
use PragmaRX\Google2FA\Google2FA;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Hash;


/* A FAIRE (fiche 3, partie 2, question 1) : inclure ci-dessous le use PHP pour la libriairie gérant l'A2F */

// A FAIRE (fiche 3, partie 3, question 4) : inclure ci-dessous le use PHP pour la libriairie gérant le JWT

class Connexion extends Controller
{
    public function afficherFormulaireConnexion() {
        return view('formulaireConnexion', []);
    }

    public function afficherFormulaireVerificationA2F() {
        if(session()->has('connexion')) {
            if(Utilisateur::where("idUtilisateur", session()->get('connexion'))->count() > 0) {
                return view('formulaireA2F', []);
            }
            else {
                session()->forget('connexion');
                return view('formulaireConnexion', []);
            }
        }
        else {
            return view('formulaireConnexion', []);
        }
    }

    public function reactivationCompte() {
        $validation = false; // Booléen vrai/faux si les conditions de vérification sont remplies pour réactiver le compte
        $messageAAfficher = null; // Contient le message d'erreur ou de succès à afficher

        /* A FAIRE (fiche 3, partie 1, question 4) : vérification du code dans l'URL ainsi que de l'expiration du lien + réactivation du compte */
        $code = request()->get('code');

        if (!$code) {
            $messageAAfficher = "Code de réactivation manquant.";
        } else {
            // Recherche du code dans la table
            $reactivation = Reactivation::where('code', $code)->first();

            if (!$reactivation) {
                $messageAAfficher = "Code de réactivation invalide.";
            } else {
                // Vérification de l'expiration du lien
                if ($reactivation->expiration < now()) {
                    $messageAAfficher = "Le lien de réactivation a expiré.";
                    // Suppression du code expiré
                    $reactivation->delete();
                } else {
                    // Réactivation du compte utilisateur
                    $utilisateur = Utilisateur::find($reactivation->idUtilisateur);
                    if ($utilisateur) {
                        $utilisateur->estDesactiveUtilisateur = 0; // Réactivation
                        $utilisateur->tentativesEchoueesUtilisateur = 0; // Réinitialisation des tentatives échouées
                        $utilisateur->save();

                        // Suppression du code de réactivation après utilisation
                        $reactivation->delete();

                        // Enregistrement dans les logs
                        Log::ecrireLog($utilisateur->email, "Réactivation réussie");

                        $validation = true;
                        $messageAAfficher = "Votre compte a été réactivé avec succès.";
                    } else {
                        $messageAAfficher = "Utilisateur introuvable.";
                    }
                }
            }
        }
        if($validation === false) {
            return view("pageErreur", ["messageErreur" => $messageAAfficher]);
        }
        else {
            return view('confirmation', ["messageConfirmation" => $messageAAfficher]);
        }
    }

    public function boutonVerificationCodeA2F() {
        $validationFormulaire = false; // Booléen qui indique si les données du formulaire sont valides
        $messagesErreur = array(); // Tableau contenant les messages d'erreur à afficher

        /* A FAIRE (fiche 3, partie 2, question 1) : vérification du code A2F */
        if (isset($_POST['codeA2F'])) {
            $codeA2F = $_POST['codeA2F'];
        
            // Récupérer l'utilisateur connecté via la session
            if (session()->has('connexion')) {
                $userId = session()->get('connexion');
                $utilisateur = Utilisateur::find($userId);  // Assurez-vous que $utilisateur est défini ici
        
                if ($utilisateur) {
                    $google2fa = new Google2FA();
        
                    // Vérification du code A2F avec la clé secrète de l'utilisateur
                    $isValid = $google2fa->verifyKey($utilisateur->cleSecreteA2F, $codeA2F);
        
                    if ($isValid) {
                        // Code A2F validé
                        $validationFormulaire = true;
        
                        // Détruire la variable SESSION (connexion)
                        session()->forget('connexion');
        
                        // Création du JWT une fois le code A2F validé
                        $key = "T3mUjGjhC6WuxyNGR2rkUt2uQgrlFUHx"; // Clé secrète pour signer le JWT
                        $payload = [
                            'name' => $utilisateur->email,            // Email de l'utilisateur
                            'sub' => $utilisateur->idUtilisateur,     // ID de l'utilisateur
                            'iat' => time()                            // Timestamp de création du JWT
                        ];
        
                        // Générer le JWT
                        $jwt = JWT::encode($payload, $key, 'HS256'); // Encodage du JWT avec la clé secrète
        
                        // Créer un cookie "auth" avec le JWT, valable pendant 30 jours
                        setcookie("auth", $jwt, time() + (30 * 24 * 60 * 60), "/", "", true, true); // Cookie sécurisé
        
                        // Redirection vers la page de profil après connexion réussie
                        return redirect()->to('profil');
                    } else {
                        // Code incorrect
                        $messagesErreur[] = "Le code d'authentification est incorrect. Veuillez réessayer.";
                    }
                } else {
                    $messagesErreur[] = "Utilisateur introuvable.";
                }
            } else {
                $messagesErreur[] = "Aucune session utilisateur active.";
            }
        } else {
            $messagesErreur[] = "Veuillez entrer un code d'authentification.";
        }
        
        // Gérer la redirection ou les erreurs
        if ($validationFormulaire) {
            // Redirection vers la page de profil si le code A2F est validé et le JWT est généré
            return redirect()->to('profil');
        } else {
            return view('formulaireA2F', ["messagesErreur" => $messagesErreur]);
        }
    }        
    
    public function boutonConnexion() {
        $validationFormulaire = false; // Booléen qui indique si les données du formulaire sont valides
        $messagesErreur = array(); // Tableau contenant les messages d'erreur à afficher

        /* A FAIRE (fiche 3, partie 1, question 3) : vérification du couple login/mot de passe */
        if(isset($_POST['email']) and isset($_POST['motdepasse'])) {
            $email = $_POST['email'];
            $motdepasse = $_POST['motdepasse'];
            // Récupérer l'utilisateur par son email
            $utilisateur = Utilisateur::where('emailUtilisateur', $email)->first();
            if(!$utilisateur) {
                $messagesErreur[] = "Aucun utilisateur trouvé avec cet email.";

            } else {
                if($utilisateur->estDesactiveUtilisateur == 1){
                    $messagesErreur[] = "Compte désactivé";
                } else {
                    if(!Hash::check($motdepasse, $utilisateur->motDePasseUtilisateur)) {
                        $messagesErreur[] = "Le mot de passe est incorrect.";
                        $utilisateur->tentativesEchoueesUtilisateur = $utilisateur->tentativesEchoueesUtilisateur + 1;
                        Log::ecrireLog($_POST["email"], "Connexion échouée");
                        if($utilisateur->tentativesEchoueesUtilisateur >= 5) {
                            $utilisateur->estDesactiveUtilisateur = 1;
                            //ENVOI MAIL
                        }                                   
                    } else {
                        $validationFormulaire = true;
                        session(['connexion' => $utilisateur->idUtilisateur]);
                        Log::ecrireLog($_POST["email"], "Connexion réussie");
                        $utilisateur->tentativesEchoueesUtilisateur = 0;

                    }
                }
                
            }
        }
        
        if($validationFormulaire === false) {
            return view('formulaireConnexion', ["messagesErreur" => $messagesErreur]);
        }
        else {
            return view('formulaireA2F', []);
        }
    }

    public function deconnexion() {
        if(session()->has('connexion')) {
            session()->forget('connexion');
        }
        if(isset($_COOKIE["auth"])) {
            setcookie("auth", "", time()-3600);
        }

        return redirect()->to('connexion')->send();
    }

    public function validationFormulaire() {
        if(isset($_POST["boutonVerificationCodeA2F"])) {
            return $this->boutonVerificationCodeA2F();
        }
        else {
            if(isset($_POST["boutonConnexion"])) {
                return $this->boutonConnexion();
            }
            else {
                return redirect()->to('connexion')->send();
            }
        }
    }
}