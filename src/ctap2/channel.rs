pub struct Channel<S: ?Sized + ChannelState> {
    channel_id: u32,
    state: S,
}

pub struct InUse;

pub struct Free;

pub trait ChannelState {}
impl ChannelState for InUse {}
impl ChannelState for Free {}

impl Channel<Free> {
    pub fn new(channel_id: u32) -> Self {
        Self {
            channel_id,
            state: Free,
        }
    }

    pub fn flip(self) -> Channel<InUse> {
        Channel::<InUse> {
            channel_id: self.channel_id,
            state: InUse {},
        }
    }
}
