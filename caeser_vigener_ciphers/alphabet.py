import dataclasses


@dataclasses.dataclass
class Alphabet:
    lower_first_letter: str
    upper_first_letter: str
    size: int
