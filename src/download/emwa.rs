pub struct MovingAverage {
    value: float64,
    DECAY: float64,
}

impl MovingAverage {
    pub fn new(age:float64) -> MovingAverage{
        MovingAverage{
            value:0,
            DECAY: age,
        }
    }

    pub fn add(&mut self,value: float64){
        if self.value == 0{
            self.value = value;
        } else {
            self.value = (value*sefl.DECAY) + (self.value * (1 - self.DECAY));
        }
    }

    pub fn value(&self) -> float64{
        self.value
    }

    pub fn set(&mut self, value:float64) {
        self.value = value;
    }
}