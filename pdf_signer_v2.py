import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# --- Constantes ---
DEFAULT_HASH_ALGORITHM = hashes.SHA256()
SIGNATURE_EXTENSION = ".sig"

class PDFSignerApp:
    def __init__(self, root_tk):
        self.root = root_tk
        self.root.title("Firmador y Verificador Digital de Documentos")
        self.root.geometry("650x450") # Ajustado para acomodar más campos

        # --- Variables de estado ---
        self.pdf_path_sign = tk.StringVar()
        self.private_key_path_sign = tk.StringVar()
        
        self.pdf_path_verify = tk.StringVar()
        self.public_key_path_verify = tk.StringVar()
        self.signature_file_path_verify = tk.StringVar()

        # --- Crear interfaz ---
        self.create_widgets()

    def create_widgets(self):
        # Crear un Notebook (pestañas)
        notebook = ttk.Notebook(self.root, padding="10")
        
        # Pestaña de Firma
        sign_frame = ttk.Frame(notebook, padding="10")
        notebook.add(sign_frame, text='Firmar Documento')
        self.create_sign_tab(sign_frame)
        
        # Pestaña de Verificación
        verify_frame = ttk.Frame(notebook, padding="10")
        notebook.add(verify_frame, text='Verificar Firma')
        self.create_verify_tab(verify_frame)
        
        notebook.pack(expand=True, fill='both')

    def create_sign_tab(self, parent_frame):
        ttk.Label(parent_frame, text="Archivo a Firmar (PDF, TXT, etc.):").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        ttk.Entry(parent_frame, textvariable=self.pdf_path_sign, width=50).grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(parent_frame, text="Buscar Archivo", command=lambda: self.select_file(self.pdf_path_sign, [("Todos los archivos", "*.*"), ("PDF Files", "*.pdf"), ("Text Files", "*.txt")])).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(parent_frame, text="Clave Privada (.pem):").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        ttk.Entry(parent_frame, textvariable=self.private_key_path_sign, width=50).grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(parent_frame, text="Buscar Clave", command=lambda: self.select_file(self.private_key_path_sign, [("PEM Files", "*.pem")])).grid(row=1, column=2, padx=5, pady=5)
        
        sign_button = ttk.Button(parent_frame, text="Firmar Documento", command=self.process_sign_document)
        sign_button.grid(row=2, column=0, columnspan=3, pady=20)
        
        self.sign_status_label = ttk.Label(parent_frame, text="Estado: Listo para firmar.")
        self.sign_status_label.grid(row=3, column=0, columnspan=3, pady=10, padx=5, sticky=tk.W)

        parent_frame.columnconfigure(1, weight=1) # Hace que la columna del Entry se expanda

    def create_verify_tab(self, parent_frame):
        ttk.Label(parent_frame, text="Archivo Original (PDF, TXT, etc.):").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        ttk.Entry(parent_frame, textvariable=self.pdf_path_verify, width=50).grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(parent_frame, text="Buscar Archivo", command=lambda: self.select_file(self.pdf_path_verify, [("Todos los archivos", "*.*"), ("PDF Files", "*.pdf"), ("Text Files", "*.txt")])).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(parent_frame, text="Archivo de Firma (.sig):").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        ttk.Entry(parent_frame, textvariable=self.signature_file_path_verify, width=50).grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(parent_frame, text="Buscar Firma", command=lambda: self.select_file(self.signature_file_path_verify, [("Signature Files", f"*{SIGNATURE_EXTENSION}")])).grid(row=1, column=2, padx=5, pady=5)

        ttk.Label(parent_frame, text="Clave Pública (.pem):").grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
        ttk.Entry(parent_frame, textvariable=self.public_key_path_verify, width=50).grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(parent_frame, text="Buscar Clave", command=lambda: self.select_file(self.public_key_path_verify, [("PEM Files", "*.pem")])).grid(row=2, column=2, padx=5, pady=5)
        
        verify_button = ttk.Button(parent_frame, text="Verificar Firma", command=self.process_verify_signature)
        verify_button.grid(row=3, column=0, columnspan=3, pady=20)
        
        self.verify_status_label = ttk.Label(parent_frame, text="Estado: Listo para verificar.")
        self.verify_status_label.grid(row=4, column=0, columnspan=3, pady=10, padx=5, sticky=tk.W)
        
        parent_frame.columnconfigure(1, weight=1) # Hace que la columna del Entry se expanda

    def select_file(self, path_variable, file_types):
        file_path = filedialog.askopenfilename(filetypes=file_types)
        if file_path:
            path_variable.set(file_path)
            
    def _generate_hash(self, file_path):
        """Genera el hash de un archivo."""
        try:
            with open(file_path, "rb") as f:
                file_content = f.read()
            hasher = hashes.Hash(DEFAULT_HASH_ALGORITHM, default_backend())
            hasher.update(file_content)
            return hasher.finalize()
        except FileNotFoundError:
            messagebox.showerror("Error", f"Archivo no encontrado: {file_path}")
            return None
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar hash: {str(e)}")
            return None

    def process_sign_document(self):
        file_to_sign = self.pdf_path_sign.get()
        private_key_file = self.private_key_path_sign.get()

        if not file_to_sign or not private_key_file:
            messagebox.showerror("Error de Entrada", "Por favor, selecciona un archivo y una clave privada.")
            return

        signature_output_path = file_to_sign + SIGNATURE_EXTENSION

        try:
            # Cargar la clave privada
            with open(private_key_file, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None, # Asume que la clave no está protegida por contraseña
                    backend=default_backend()
                )
            
            # Generar el hash del archivo
            file_hash = self._generate_hash(file_to_sign)
            if file_hash is None:
                self.sign_status_label.config(text="Error: No se pudo generar el hash del archivo.")
                return

            # Firmar el hash
            signature = private_key.sign(
                file_hash,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(DEFAULT_HASH_ALGORITHM),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                DEFAULT_HASH_ALGORITHM
            )
            
            signature_b64 = base64.b64encode(signature).decode('utf-8')

            # Guardar la firma en un archivo
            with open(signature_output_path, "w") as f:
                f.write(signature_b64)
            
            self.sign_status_label.config(text=f"¡Éxito! Documento firmado. Firma guardada en: {signature_output_path}")
            messagebox.showinfo("Firma Exitosa", f"Documento firmado y firma guardada en:\n{signature_output_path}")

        except FileNotFoundError as e:
            self.sign_status_label.config(text=f"Error: Archivo no encontrado - {e.filename}")
            messagebox.showerror("Error de Archivo", f"No se pudo encontrar el archivo: {e.filename}")
        except Exception as e:
            self.sign_status_label.config(text=f"Error al firmar: {str(e)}")
            messagebox.showerror("Error de Firma", f"Ocurrió un error al firmar el documento:\n{str(e)}")

    def process_verify_signature(self):
        original_file = self.pdf_path_verify.get()
        signature_file = self.signature_file_path_verify.get()
        public_key_file = self.public_key_path_verify.get()

        if not original_file or not signature_file or not public_key_file:
            messagebox.showerror("Error de Entrada", "Por favor, selecciona el archivo original, el archivo de firma y la clave pública.")
            return

        try:
            # Cargar la clave pública
            with open(public_key_file, "rb") as key_file_obj: # Renombrado para evitar conflicto
                public_key = serialization.load_pem_public_key(
                    key_file_obj.read(),
                    backend=default_backend()
                )

            # Leer la firma del archivo (decodificar de Base64)
            with open(signature_file, "r") as f:
                signature_b64 = f.read()
            signature = base64.b64decode(signature_b64)

            # Generar el hash del archivo original
            file_hash = self._generate_hash(original_file)
            if file_hash is None:
                self.verify_status_label.config(text="Error: No se pudo generar el hash del archivo original.")
                return
            
            # Verificar la firma
            public_key.verify(
                signature,
                file_hash,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(DEFAULT_HASH_ALGORITHM),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                DEFAULT_HASH_ALGORITHM
            )
            
            self.verify_status_label.config(text="¡Éxito! La firma es VÁLIDA.")
            messagebox.showinfo("Verificación Exitosa", "La firma del documento es VÁLIDA.")

        except FileNotFoundError as e:
            self.verify_status_label.config(text=f"Error: Archivo no encontrado - {e.filename}")
            messagebox.showerror("Error de Archivo", f"No se pudo encontrar el archivo: {e.filename}")
        except InvalidSignature:
            self.verify_status_label.config(text="Error: ¡FIRMA INVÁLIDA!")
            messagebox.showerror("Verificación Fallida", "La firma del documento es INVÁLIDA.")
        except Exception as e:
            self.verify_status_label.config(text=f"Error durante la verificación: {str(e)}")
            messagebox.showerror("Error de Verificación", f"Ocurrió un error durante la verificación:\n{str(e)}")


if __name__ == "__main__":
    main_root = tk.Tk()
    app = PDFSignerApp(main_root)
    main_root.mainloop()
