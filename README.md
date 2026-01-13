# Timetable (RTT proxy)

Lekki proxy RTT dla dashboardu TfL. Serwer pobiera odjazdy z RTT, filtruje
przejazdy przez HHY i wystawia prosty JSON dla frontendu.

## Wymagania
- Python 3.9+ (dziala rowniez na nowszych)
- Pakiety: `flask`, `requests`, `python-dotenv`

## Konfiguracja
1. Utworz plik `.env` w katalogu projektu:
   - `RTT_USER` – login do RTT
   - `RTT_PASS` – haslo do RTT

2. Zainstaluj zaleznosci:
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install flask requests python-dotenv
```

## Uruchomienie
```bash
python rtt_proxy.py
```

Serwer startuje na `http://127.0.0.1:5010`.

## Endpointy
`GET /api/trains`
- Zwraca odjazdy z AAP jadace przez HHY (kierunek AAP -> HHY).
- Frontend moze sortowac i wyswietlac najblizsze kursy.
- Dla anulowanych przejazdow:
  - `cancelled` = `true`
  - `etd` = `"Anulowane"`

Przyklady odpowiedzi:
```json
{
  "services": [
    {
      "destination": "London",
      "std": "12:34",
      "etd": "On time",
      "platform": "2",
      "runDate": "2026-01-13",
      "operator": "X",
      "trainId": "1234",
      "cancelled": false
    }
  ],
  "fetched_at": "2026-01-13T19:00:00Z"
}
```

## Uwagi
- Proxy stosuje cache TTL dla sprawdzen HHY, z limitem rozmiaru.
- CORS jest skonfigurowany tak, aby dzialal takze z `file://` i `localhost`.
