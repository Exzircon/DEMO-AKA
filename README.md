# Gruppeoppgave 3 - DEMO AKA

Av: Christoffer Simonsen, Daniel Hao Huynh, Mikael Fossli<br>
[Milenage Implementation](https://github.com/Exzircon/MILENAGE/blob/Ref-deliver/oblig1.py)<br>

Dette er vår implementasjon av DEKO-AKA, som er en Python-implementasjon av UMTS-AKA, der hovedkensikten er å demonstrere virkemåte. Kryptografien i UMTS-AKA er basert på MILENAGE. Over er en linke til vår tidligere implementasjon av MILENAGE som vi brukte i dette prosjektet.

### Oppsett av prosjekt

1. sett opp virtuell miljø:

-   https://docs.python.org/3/library/venv.html

2. aktiver miljø

-   ```sh
    .\.venv\Scripts\activate
    ```

3. hent nødvendige moduler:

-   ```sh
    pip install -r .\requirements.txt
    ```

### Conformance Test

Resultatene er lagret i _home_run.txt_ og _usim_run.txt_.

For å reprodusere resultatene må først _HOME.py_ startes, deretter _USIM.py_.

```sh
python HOME.py
```

```sh
python USIM.py
```
